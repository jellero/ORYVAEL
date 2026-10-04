#![no_std]
#![no_main]

use core::ffi::c_void;
use core::panic::PanicInfo;

mod arch;
mod boot;
mod console;
mod io;
mod memory;
mod userspace;

use boot::{EfiHandle, EfiStatus};
use memory::{FrameAllocator, KernelHeap, PageTables};

#[unsafe(export_name = "efi_main")]
pub extern "efiapi" fn efi_main(image_handle: EfiHandle, system_table: *mut c_void) -> EfiStatus {
    io::serial_init();
    io::serial_write("\r\nORYVAEL: firmware entry\r\n");

    // SAFETY: UEFI owns the system table until the explicit handoff below.
    let Some(boot_services) = (unsafe { boot::boot_services_from_system_table(system_table) }) else {
        io::serial_write("ORYVAEL: invalid UEFI system table\r\n");
        return 1;
    };

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
    io::serial_write("ORYVAEL: firmware boot services detached\r\n");
    io::serial_write("ORYVAEL: bare-metal kernel online\r\n");
    io::serial_write("ORYVAEL: no Linux kernel\r\n");

    let mut frames = FrameAllocator::from_boot_map(&boot_map);
    io::serial_write("ORYVAEL: physical allocator online regions=");
    io::serial_write_u64(frames.region_count() as u64);
    io::serial_write(" free_pages=");
    io::serial_write_u64(frames.free_pages());
    io::serial_write("\r\n");

    let mut heap = KernelHeap::new();
    let Some(heap_probe) = heap.alloc(64, 16) else {
        io::serial_write("ORYVAEL: kernel heap initialization failed\r\n");
        return 2;
    };
    // SAFETY: heap_probe is the 64-byte allocation just reserved above.
    unsafe { core::ptr::write_bytes(heap_probe as *mut u8, 0xa5, 64) };
    io::serial_write("ORYVAEL: kernel heap online bytes=");
    io::serial_write_u64(heap.capacity() as u64);
    io::serial_write("\r\n");

    let Some(mut page_tables) = PageTables::take_ownership() else {
        io::serial_write("ORYVAEL: page-table takeover failed\r\n");
        return 3;
    };
    io::serial_write("ORYVAEL: page tables online cr3=");
    io::serial_write_hex(page_tables.root_phys());
    io::serial_write("\r\n");

    if !arch::initialize() {
        io::serial_write("ORYVAEL: interrupt/timer self-test failed\r\n");
        return 4;
    }
    io::serial_write("ORYVAEL: exceptions online vectors=32\r\n");
    io::serial_write("ORYVAEL: timer interrupts online hz=");
    io::serial_write_u64(arch::TIMER_HZ);
    io::serial_write("\r\n");

    let Some(user) = userspace::prepare_and_run(&mut page_tables) else {
        io::serial_write("ORYVAEL: userspace bootstrap failed\r\n");
        return 5;
    };
    if user.exit_code != 0 || user.preemptions == 0 {
        io::serial_write("ORYVAEL: userspace scheduler self-test failed\r\n");
        return 6;
    }
    io::serial_write("ORYVAEL: scheduler online runnable=0 completed=1 ring3_preemptions=");
    io::serial_write_u64(user.preemptions);
    io::serial_write("\r\n");

    io::serial_write("ORYVAEL: memory descriptors=");
    io::serial_write_u64(boot_map.descriptors as u64);
    io::serial_write(" conventional_pages=");
    io::serial_write_u64(boot_map.conventional_pages);
    io::serial_write(" reclaimable_pages=");
    io::serial_write_u64(boot_map.reclaimable_pages);
    io::serial_write(" runtime_pages=");
    io::serial_write_u64(boot_map.runtime_pages);
    io::serial_write("\r\n");
    io::serial_write("ORYVAEL: native minimal OS ready\r\n");

    console::run(&mut frames, &mut heap, &page_tables)
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    io::disable_interrupts();
    io::serial_init();
    io::serial_write("\r\nORYVAEL: KERNEL PANIC\r\n");
    io::halt_forever()
}
