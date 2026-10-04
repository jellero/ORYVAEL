#![no_std]
#![no_main]

use core::arch::asm;
use core::ffi::c_void;
use core::mem::size_of;
use core::panic::PanicInfo;

// Stage 0 has one architecture target: x86_64 machines booted by UEFI.
// UEFI is used only for the firmware handoff. After ExitBootServices succeeds,
// ORYVAEL continues without firmware boot services and without another OS.

type EfiStatus = usize;
type EfiHandle = *mut c_void;

const EFI_SUCCESS: EfiStatus = 0;
const MEMORY_MAP_CAPACITY: usize = 128 * 1024;
const COM1: u16 = 0x3f8;

const EFI_LOADER_CODE: u32 = 1;
const EFI_LOADER_DATA: u32 = 2;
const EFI_BOOT_SERVICES_CODE: u32 = 3;
const EFI_BOOT_SERVICES_DATA: u32 = 4;
const EFI_RUNTIME_SERVICES_CODE: u32 = 5;
const EFI_RUNTIME_SERVICES_DATA: u32 = 6;
const EFI_CONVENTIONAL_MEMORY: u32 = 7;

#[repr(C)]
struct EfiTableHeader {
    signature: u64,
    revision: u32,
    header_size: u32,
    crc32: u32,
    reserved: u32,
}

type EfiGetMemoryMap = unsafe extern "efiapi" fn(
    memory_map_size: *mut usize,
    memory_map: *mut EfiMemoryDescriptor,
    map_key: *mut usize,
    descriptor_size: *mut usize,
    descriptor_version: *mut u32,
) -> EfiStatus;

type EfiExitBootServices =
    unsafe extern "efiapi" fn(image_handle: EfiHandle, map_key: usize) -> EfiStatus;

// Prefix of EFI_BOOT_SERVICES through ExitBootServices. Keeping the exact UEFI
// field order lets Stage 0 avoid a firmware abstraction crate in the kernel.
#[repr(C)]
struct EfiBootServices {
    header: EfiTableHeader,
    raise_tpl: usize,
    restore_tpl: usize,
    allocate_pages: usize,
    free_pages: usize,
    get_memory_map: EfiGetMemoryMap,
    allocate_pool: usize,
    free_pool: usize,
    create_event: usize,
    set_timer: usize,
    wait_for_event: usize,
    signal_event: usize,
    close_event: usize,
    check_event: usize,
    install_protocol_interface: usize,
    reinstall_protocol_interface: usize,
    uninstall_protocol_interface: usize,
    handle_protocol: usize,
    reserved: usize,
    register_protocol_notify: usize,
    locate_handle: usize,
    locate_device_path: usize,
    install_configuration_table: usize,
    load_image: usize,
    start_image: usize,
    exit: usize,
    unload_image: usize,
    exit_boot_services: EfiExitBootServices,
}

#[repr(C)]
struct EfiSystemTable {
    header: EfiTableHeader,
    firmware_vendor: *mut u16,
    firmware_revision: u32,
    console_in_handle: EfiHandle,
    con_in: *mut c_void,
    console_out_handle: EfiHandle,
    con_out: *mut c_void,
    standard_error_handle: EfiHandle,
    stderr: *mut c_void,
    runtime_services: *mut c_void,
    boot_services: *mut EfiBootServices,
    number_of_table_entries: usize,
    configuration_table: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct EfiMemoryDescriptor {
    memory_type: u32,
    _padding: u32,
    physical_start: u64,
    virtual_start: u64,
    number_of_pages: u64,
    attribute: u64,
}

#[repr(align(16))]
struct AlignedMemoryMap([u8; MEMORY_MAP_CAPACITY]);

static mut MEMORY_MAP: AlignedMemoryMap = AlignedMemoryMap([0; MEMORY_MAP_CAPACITY]);

#[derive(Clone, Copy)]
struct MemorySummary {
    descriptors: usize,
    reclaimable_pages: u64,
    runtime_pages: u64,
}

#[unsafe(export_name = "efi_main")]
pub extern "efiapi" fn efi_main(
    image_handle: EfiHandle,
    system_table: *mut EfiSystemTable,
) -> EfiStatus {
    serial_init();
    serial_write("\r\nORYVAEL: firmware entry\r\n");

    if system_table.is_null() {
        serial_write("ORYVAEL: invalid UEFI system table\r\n");
        return 1;
    }

    // SAFETY: UEFI passes a valid EFI_SYSTEM_TABLE pointer to efi_main while
    // boot services are active. We only read the BootServices field here.
    let boot_services = unsafe { (*system_table).boot_services };
    if boot_services.is_null() {
        serial_write("ORYVAEL: boot services unavailable\r\n");
        return 1;
    }

    // SAFETY: image_handle, system_table and the BootServices function table
    // are supplied by UEFI. detach_firmware performs the required final memory
    // map acquisition immediately before ExitBootServices and retries if the
    // map key changes.
    let summary = match unsafe { detach_firmware(image_handle, boot_services) } {
        Ok(summary) => summary,
        Err(status) => {
            serial_write("ORYVAEL: firmware handoff failed status=");
            serial_write_hex(status as u64);
            serial_write("\r\n");
            return status;
        }
    };

    disable_interrupts();
    serial_write("ORYVAEL: firmware boot services detached\r\n");
    serial_write("ORYVAEL: bare-metal kernel online\r\n");
    serial_write("ORYVAEL: memory descriptors=");
    serial_write_u64(summary.descriptors as u64);
    serial_write(" reclaimable_pages=");
    serial_write_u64(summary.reclaimable_pages);
    serial_write(" runtime_pages=");
    serial_write_u64(summary.runtime_pages);
    serial_write("\r\n");
    serial_write("ORYVAEL: no Linux kernel; entering kernel idle\r\n");

    halt_forever()
}

unsafe fn detach_firmware(
    image_handle: EfiHandle,
    boot_services: *mut EfiBootServices,
) -> Result<MemorySummary, EfiStatus> {
    // SAFETY: boot_services points at the firmware-owned EFI_BOOT_SERVICES
    // table while boot services are active.
    let get_memory_map = unsafe { (*boot_services).get_memory_map };
    // SAFETY: same table and lifetime as above.
    let exit_boot_services = unsafe { (*boot_services).exit_boot_services };

    for _ in 0..4 {
        let mut map_size = MEMORY_MAP_CAPACITY;
        let mut map_key = 0usize;
        let mut descriptor_size = 0usize;
        let mut descriptor_version = 0u32;

        // SAFETY: addr_of_mut! creates a raw pointer without creating a
        // reference to the static mut buffer. The buffer is exclusively used
        // by the single boot CPU during this handoff.
        let map_ptr = core::ptr::addr_of_mut!(MEMORY_MAP.0).cast::<u8>();

        // SAFETY: map_ptr addresses MEMORY_MAP_CAPACITY writable bytes and all
        // scalar out-parameters are valid for the duration of this call.
        let map_status = unsafe {
            get_memory_map(
                &mut map_size,
                map_ptr.cast::<EfiMemoryDescriptor>(),
                &mut map_key,
                &mut descriptor_size,
                &mut descriptor_version,
            )
        };
        if map_status != EFI_SUCCESS {
            return Err(map_status);
        }

        // SAFETY: GetMemoryMap succeeded, so map_size bytes in the static
        // buffer contain descriptors with the returned descriptor_size.
        let summary = unsafe { summarize_memory(map_ptr, map_size, descriptor_size) };

        // SAFETY: UEFI requires the latest map key from GetMemoryMap. No UEFI
        // allocation or protocol operation occurs between these two calls.
        let exit_status = unsafe { exit_boot_services(image_handle, map_key) };
        if exit_status == EFI_SUCCESS {
            return Ok(summary);
        }

        // A stale map key is recoverable by acquiring a fresh map and trying
        // again. No other boot service is called after the first exit attempt.
    }

    Err(usize::MAX)
}

unsafe fn summarize_memory(
    map_ptr: *const u8,
    map_size: usize,
    descriptor_size: usize,
) -> MemorySummary {
    if descriptor_size < size_of::<EfiMemoryDescriptor>() || descriptor_size == 0 {
        return MemorySummary {
            descriptors: 0,
            reclaimable_pages: 0,
            runtime_pages: 0,
        };
    }

    let mut offset = 0usize;
    let mut descriptors = 0usize;
    let mut reclaimable_pages = 0u64;
    let mut runtime_pages = 0u64;

    while offset.saturating_add(descriptor_size) <= map_size {
        // SAFETY: offset is bounded by map_size and GetMemoryMap guarantees at
        // least descriptor_size bytes per entry. read_unaligned avoids relying
        // on firmware descriptor alignment.
        let descriptor = unsafe {
            core::ptr::read_unaligned(map_ptr.add(offset).cast::<EfiMemoryDescriptor>())
        };

        descriptors += 1;
        match descriptor.memory_type {
            EFI_LOADER_CODE
            | EFI_LOADER_DATA
            | EFI_BOOT_SERVICES_CODE
            | EFI_BOOT_SERVICES_DATA
            | EFI_CONVENTIONAL_MEMORY => {
                reclaimable_pages = reclaimable_pages.saturating_add(descriptor.number_of_pages);
            }
            EFI_RUNTIME_SERVICES_CODE | EFI_RUNTIME_SERVICES_DATA => {
                runtime_pages = runtime_pages.saturating_add(descriptor.number_of_pages);
            }
            _ => {}
        }

        offset += descriptor_size;
    }

    MemorySummary {
        descriptors,
        reclaimable_pages,
        runtime_pages,
    }
}

fn serial_init() {
    // SAFETY: COM1 is the legacy x86_64 UART I/O range. Stage 0 targets QEMU
    // and PC-compatible x86_64 firmware where these ports are architecturally
    // available. No memory safety invariant depends on serial availability.
    unsafe {
        outb(COM1 + 1, 0x00);
        outb(COM1 + 3, 0x80);
        outb(COM1, 0x03);
        outb(COM1 + 1, 0x00);
        outb(COM1 + 3, 0x03);
        outb(COM1 + 2, 0xc7);
        outb(COM1 + 4, 0x0b);
    }
}

fn serial_write(text: &str) {
    for byte in text.bytes() {
        serial_write_byte(byte);
    }
}

fn serial_write_byte(byte: u8) {
    for _ in 0..100_000 {
        // SAFETY: reading the UART line-status register is an x86 port-I/O
        // operation confined to the documented COM1 range.
        if unsafe { inb(COM1 + 5) } & 0x20 != 0 {
            break;
        }
        core::hint::spin_loop();
    }

    // SAFETY: writing COM1 transmits one diagnostic byte. This does not expose
    // memory or authority to firmware after ExitBootServices.
    unsafe { outb(COM1, byte) };
}

fn serial_write_u64(mut value: u64) {
    if value == 0 {
        serial_write_byte(b'0');
        return;
    }

    let mut digits = [0u8; 20];
    let mut used = 0usize;
    while value != 0 {
        digits[used] = b'0' + (value % 10) as u8;
        used += 1;
        value /= 10;
    }

    while used != 0 {
        used -= 1;
        serial_write_byte(digits[used]);
    }
}

fn serial_write_hex(value: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    serial_write("0x");
    for shift in (0..16).rev() {
        let nibble = ((value >> (shift * 4)) & 0xf) as usize;
        serial_write_byte(HEX[nibble]);
    }
}

fn disable_interrupts() {
    // SAFETY: after firmware handoff ORYVAEL has not installed its IDT yet, so
    // maskable interrupts must stay disabled until the kernel owns that path.
    unsafe { asm!("cli", options(nomem, nostack)) };
}

fn halt_forever() -> ! {
    disable_interrupts();
    loop {
        // SAFETY: HLT is the intended Stage 0 idle state with interrupts
        // disabled. Later scheduler work will replace this path.
        unsafe { asm!("hlt", options(nomem, nostack)) };
    }
}

unsafe fn outb(port: u16, value: u8) {
    // SAFETY: caller is responsible for selecting a valid x86 I/O port.
    unsafe {
        asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack, preserves_flags)
        )
    };
}

unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: caller is responsible for selecting a valid x86 I/O port.
    unsafe {
        asm!(
            "in al, dx",
            in("dx") port,
            out("al") value,
            options(nomem, nostack, preserves_flags)
        )
    };
    value
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    serial_init();
    serial_write("\r\nORYVAEL: KERNEL PANIC\r\n");
    halt_forever()
}
