#![no_std]
#![no_main]

use core::ffi::c_void;
use core::panic::PanicInfo;

mod accounts;
mod arch;
mod boot;
mod console;
mod graphics;
mod io;
mod memory;
mod network;
mod ssh_server;
mod userspace;

use boot::{BootGraphics, EfiHandle, EfiStatus};
use memory::{FrameAllocator, KernelHeap, PageTables};

#[unsafe(export_name = "efi_main")]
pub extern "efiapi" fn efi_main(image_handle: EfiHandle, system_table: *mut c_void) -> EfiStatus {
    io::serial_init();
    io::serial_write("\x1b[2J\x1b[H");
    io::serial_write("\x1b[1;36m");
    io::serial_write("============================================================\r\n");
    io::serial_write("                      O R Y V A E L                       \r\n");
    io::serial_write("============================================================\r\n");
    io::serial_write("\x1b[0m");
    io::serial_write(" Sovereign AI-Native Operating System  |  x86_64 UEFI\r\n");
    io::serial_write(" Intelligence proposes. Humans authorize. ORYVAEL enforces.\r\n\r\n");
    io::serial_write("\x1b[2mBoot sequence\x1b[0m\r\n");
    boot_ok("Firmware entry accepted");

    // SAFETY: UEFI owns the system table until the explicit handoff below.
    let Some(boot_services) = (unsafe { boot::boot_services_from_system_table(system_table) })
    else {
        io::serial_write("ORYVAEL: invalid UEFI system table\r\n");
        return 1;
    };

    // Capture graphics state and reserve a backbuffer while Boot Services are
    // still live. Failure is non-fatal: serial remains the recovery console.
    let graphics_boot = unsafe { boot::prepare_graphics(system_table) };

    // SAFETY: image handle and boot-services table are supplied by UEFI.
    let boot_map = match unsafe { boot::detach_firmware(image_handle, boot_services) } {
        Ok(map) => map,
        Err(status) => {
            io::serial_write("ORYVAEL: firmware handoff failed status=");
            io::serial_write_hex(status as u64);
            io::serial_write("\r\n");
            return status;
        }
    };

    io::disable_interrupts();
    boot_ok("Firmware handoff complete");
    boot_ok("Native kernel online");

    let mut frames = FrameAllocator::from_boot_map(&boot_map);
    boot_ok("Physical memory manager online");
    boot_info_u64("Usable memory regions", frames.region_count() as u64);
    boot_info_u64(
        "Free physical memory (MiB)",
        frames.free_pages().saturating_mul(memory::PAGE_SIZE) / (1024 * 1024),
    );

    let mut heap = KernelHeap::new();
    let Some(heap_probe) = heap.alloc(64, 16) else {
        io::serial_write("ORYVAEL: kernel heap initialization failed\r\n");
        return 2;
    };
    // SAFETY: heap_probe is the 64-byte allocation just reserved above.
    unsafe { core::ptr::write_bytes(heap_probe as *mut u8, 0xa5, 64) };
    boot_ok("Kernel heap online");
    boot_info_u64("Kernel heap capacity (KiB)", heap.capacity() as u64 / 1024);

    let Some(mut page_tables) = PageTables::take_ownership() else {
        io::serial_write("ORYVAEL: page-table takeover failed\r\n");
        return 3;
    };
    boot_ok("Virtual memory ownership established");
    boot_info_hex("Active page table (CR3)", page_tables.root_phys());

    if !arch::initialize() {
        io::serial_write("ORYVAEL: interrupt/timer self-test failed\r\n");
        return 4;
    }
    boot_ok("Exception and interrupt gates online");
    boot_ok("System clock online at 100 Hz");
    boot_info("Exception vectors", "32");
    boot_info("Syscall gateway", "int 0x80 / DPL3");
    boot_info_hex("Userspace base", userspace::USER_CODE_VA);

    initialize_graphics(graphics_boot, &page_tables);

    let Some(user) = userspace::prepare_and_run(&mut page_tables) else {
        io::serial_write("ORYVAEL: userspace bootstrap failed\r\n");
        return 5;
    };
    if user.exit_code != 0 || user.preemptions == 0 {
        io::serial_write("ORYVAEL: userspace scheduler self-test failed\r\n");
        return 6;
    }
    boot_info_u64("Ring-3 timer preemptions", user.preemptions);

    boot_info("Network HAL", "probing PCI bus");
    if network::initialize(&page_tables) {
        boot_ok("RTL8139 network device online");
        if network::configured() {
            boot_ok("DHCP lease acquired");
            boot_info_ip("IPv4 address", network::snapshot().ipv4);
            boot_info_ip("Default gateway", network::snapshot().gateway);
        } else {
            boot_warn("DHCP did not provide a lease");
        }
    } else {
        boot_warn("No supported network device found");
    }
    boot_ok("Scheduler and recovery console ready");
    io::serial_write("\r\n\x1b[1;32mORYVAEL SYSTEM READY\x1b[0m\r\n");

    console::run(&mut frames, &mut heap, &page_tables, &boot_map)
}

fn initialize_graphics(graphics_boot: Option<BootGraphics>, page_tables: &PageTables) {
    let Some(info) = graphics_boot else {
        boot_warn("No supported UEFI GOP framebuffer found");
        return;
    };

    if !graphics_mapping_available(page_tables, info.framebuffer_base, info.framebuffer_size) {
        boot_warn("GOP framebuffer is outside the inherited kernel mapping");
        return;
    }
    if info.backbuffer_base != 0
        && !graphics_mapping_available(page_tables, info.backbuffer_base, info.backbuffer_size)
    {
        boot_warn("Graphics backbuffer is outside the inherited kernel mapping");
        return;
    }

    let Some(mut display) = graphics::Graphics::new(info) else {
        boot_warn("GOP mode is unsupported by the native graphics engine");
        return;
    };

    boot_ok("Native graphics engine online");
    boot_info_u64("Display width", display.width() as u64);
    boot_info_u64("Display height", display.height() as u64);
    boot_info(
        "Graphics buffering",
        if display.uses_backbuffer() {
            "software backbuffer"
        } else {
            "direct framebuffer"
        },
    );
    graphics::run_boot_animation(&mut display);
    boot_ok("Framebuffer animation self-test complete");
}

fn graphics_mapping_available(page_tables: &PageTables, base: u64, size: usize) -> bool {
    if base == 0 || size == 0 {
        return false;
    }
    let Some(last) = base.checked_add(size.saturating_sub(1) as u64) else {
        return false;
    };
    page_tables.translate_kernel_va(base).is_some()
        && page_tables.translate_kernel_va(last).is_some()
}

fn boot_ok(message: &str) {
    io::serial_write(" \x1b[1;32m[  OK  ]\x1b[0m ");
    io::serial_write(message);
    io::serial_write("\r\n");
}

fn boot_info(label: &str, value: &str) {
    io::serial_write(" \x1b[1;36m[ INFO ]\x1b[0m ");
    io::serial_write(label);
    io::serial_write(": ");
    io::serial_write(value);
    io::serial_write("\r\n");
}

fn boot_info_u64(label: &str, value: u64) {
    io::serial_write(" \x1b[1;36m[ INFO ]\x1b[0m ");
    io::serial_write(label);
    io::serial_write(": ");
    io::serial_write_u64(value);
    io::serial_write("\r\n");
}

fn boot_info_hex(label: &str, value: u64) {
    io::serial_write(" \x1b[1;36m[ INFO ]\x1b[0m ");
    io::serial_write(label);
    io::serial_write(": ");
    io::serial_write_hex(value);
    io::serial_write("\r\n");
}

fn boot_info_ip(label: &str, value: [u8; 4]) {
    io::serial_write(" \x1b[1;36m[ INFO ]\x1b[0m ");
    io::serial_write(label);
    io::serial_write(": ");
    for (index, octet) in value.iter().enumerate() {
        if index != 0 {
            io::serial_write_byte(b'.');
        }
        io::serial_write_u64(*octet as u64);
    }
    io::serial_write("\r\n");
}

fn boot_warn(message: &str) {
    io::serial_write(" \x1b[1;33m[ WARN ]\x1b[0m ");
    io::serial_write(message);
    io::serial_write("\r\n");
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    io::disable_interrupts();
    io::serial_init();
    io::serial_write("\r\nORYVAEL: KERNEL PANIC\r\n");
    io::halt_forever()
}
