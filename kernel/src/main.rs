#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::ffi::c_void;
use core::mem::size_of;
use core::panic::PanicInfo;

// ORYVAEL minimal bare-metal base, x86_64/UEFI.
// UEFI is only the firmware handoff. After ExitBootServices succeeds, the
// kernel owns its allocator, interrupt table, timer and console loop.

type EfiStatus = usize;
type EfiHandle = *mut c_void;

const EFI_SUCCESS: EfiStatus = 0;
const MEMORY_MAP_CAPACITY: usize = 128 * 1024;
const PAGE_SIZE: u64 = 4096;
const LOW_MEMORY_CUTOFF: u64 = 0x10_0000;
const MAX_FRAME_REGIONS: usize = 64;
const KERNEL_HEAP_BYTES: usize = 256 * 1024;
const TIMER_HZ: u64 = 100;

const COM1: u16 = 0x3f8;
const PIC1_COMMAND: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_COMMAND: u16 = 0xa0;
const PIC2_DATA: u16 = 0xa1;
const PIT_CHANNEL0: u16 = 0x40;
const PIT_COMMAND: u16 = 0x43;
const PIT_BASE_HZ: u64 = 1_193_182;
const PS2_DATA: u16 = 0x60;
const PS2_STATUS_COMMAND: u16 = 0x64;

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
struct BootMemoryMap {
    map_ptr: *const u8,
    map_size: usize,
    descriptor_size: usize,
    descriptors: usize,
    reclaimable_pages: u64,
    conventional_pages: u64,
    runtime_pages: u64,
}

#[derive(Clone, Copy)]
struct FrameRegion {
    next: u64,
    end: u64,
}

const EMPTY_FRAME_REGION: FrameRegion = FrameRegion { next: 0, end: 0 };

struct FrameAllocator {
    regions: [FrameRegion; MAX_FRAME_REGIONS],
    region_count: usize,
    cursor: usize,
    free_pages: u64,
}

impl FrameAllocator {
    fn from_boot_map(map: &BootMemoryMap) -> Self {
        let mut allocator = Self {
            regions: [EMPTY_FRAME_REGION; MAX_FRAME_REGIONS],
            region_count: 0,
            cursor: 0,
            free_pages: 0,
        };

        if map.descriptor_size < size_of::<EfiMemoryDescriptor>() || map.descriptor_size == 0 {
            return allocator;
        }

        let mut offset = 0usize;
        while offset.saturating_add(map.descriptor_size) <= map.map_size {
            // SAFETY: map_ptr points into the retained static firmware map and
            // offset is bounded by the map size returned by GetMemoryMap.
            let descriptor = unsafe {
                core::ptr::read_unaligned(
                    map.map_ptr.add(offset).cast::<EfiMemoryDescriptor>(),
                )
            };

            if descriptor.memory_type == EFI_CONVENTIONAL_MEMORY
                && allocator.region_count < MAX_FRAME_REGIONS
            {
                let raw_start = descriptor.physical_start.max(LOW_MEMORY_CUTOFF);
                let raw_end = descriptor
                    .physical_start
                    .saturating_add(descriptor.number_of_pages.saturating_mul(PAGE_SIZE));
                let start = align_up_u64(raw_start, PAGE_SIZE);
                let end = align_down_u64(raw_end, PAGE_SIZE);

                if start < end {
                    let pages = (end - start) / PAGE_SIZE;
                    allocator.regions[allocator.region_count] = FrameRegion { next: start, end };
                    allocator.region_count += 1;
                    allocator.free_pages = allocator.free_pages.saturating_add(pages);
                }
            }

            offset += map.descriptor_size;
        }

        allocator
    }

    fn alloc_frame(&mut self) -> Option<u64> {
        while self.cursor < self.region_count {
            let region = &mut self.regions[self.cursor];
            if region.next < region.end {
                let frame = region.next;
                region.next = region.next.saturating_add(PAGE_SIZE);
                self.free_pages = self.free_pages.saturating_sub(1);
                return Some(frame);
            }
            self.cursor += 1;
        }
        None
    }

    fn free_pages(&self) -> u64 {
        self.free_pages
    }

    fn region_count(&self) -> usize {
        self.region_count
    }
}

#[repr(align(64))]
struct HeapStorage([u8; KERNEL_HEAP_BYTES]);

static mut KERNEL_HEAP_STORAGE: HeapStorage = HeapStorage([0; KERNEL_HEAP_BYTES]);

struct KernelHeap {
    start: usize,
    next: usize,
    end: usize,
}

impl KernelHeap {
    fn new() -> Self {
        // SAFETY: Stage 1 is single-core and the heap storage is owned solely
        // by this allocator after firmware handoff.
        let start = unsafe { core::ptr::addr_of_mut!(KERNEL_HEAP_STORAGE.0).cast::<u8>() as usize };
        Self {
            start,
            next: start,
            end: start + KERNEL_HEAP_BYTES,
        }
    }

    fn alloc(&mut self, bytes: usize, alignment: usize) -> Option<usize> {
        let alignment = alignment.max(1);
        if !alignment.is_power_of_two() {
            return None;
        }
        let aligned = align_up_usize(self.next, alignment)?;
        let end = aligned.checked_add(bytes)?;
        if end > self.end {
            return None;
        }
        self.next = end;
        Some(aligned)
    }

    fn used(&self) -> usize {
        self.next - self.start
    }

    fn free(&self) -> usize {
        self.end - self.next
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    attributes: u8,
    offset_mid: u16,
    offset_high: u32,
    zero: u32,
}

impl IdtEntry {
    const MISSING: Self = Self {
        offset_low: 0,
        selector: 0,
        ist: 0,
        attributes: 0,
        offset_mid: 0,
        offset_high: 0,
        zero: 0,
    };

    fn interrupt_gate(handler: u64, selector: u16) -> Self {
        Self {
            offset_low: handler as u16,
            selector,
            ist: 0,
            attributes: 0x8e,
            offset_mid: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            zero: 0,
        }
    }
}

#[repr(align(16))]
struct AlignedIdt([IdtEntry; 256]);

static mut IDT: AlignedIdt = AlignedIdt([IdtEntry::MISSING; 256]);

#[repr(C, packed)]
struct Idtr {
    limit: u16,
    base: u64,
}

#[unsafe(no_mangle)]
pub static mut ORYVAEL_TICKS: u64 = 0;

unsafe extern "C" {
    fn oryvael_timer_interrupt();
}

global_asm!(
    ".global oryvael_timer_interrupt",
    "oryvael_timer_interrupt:",
    "push rax",
    "push rdx",
    "inc qword ptr [rip + ORYVAEL_TICKS]",
    "mov dx, 0x20",
    "mov al, 0x20",
    "out dx, al",
    "pop rdx",
    "pop rax",
    "iretq",
);

#[unsafe(export_name = "efi_main")]
pub extern "efiapi" fn efi_main(image_handle: EfiHandle, system_table: *mut c_void) -> EfiStatus {
    serial_init();
    serial_write("\r\nORYVAEL: firmware entry\r\n");

    if system_table.is_null() {
        serial_write("ORYVAEL: invalid UEFI system table\r\n");
        return 1;
    }

    let system_table = system_table.cast::<EfiSystemTable>();

    // SAFETY: UEFI passes a valid EFI_SYSTEM_TABLE pointer to efi_main while
    // boot services are active. We only read the BootServices field here.
    let boot_services = unsafe { (*system_table).boot_services };
    if boot_services.is_null() {
        serial_write("ORYVAEL: boot services unavailable\r\n");
        return 1;
    }

    // SAFETY: the supplied firmware tables are valid until ExitBootServices.
    let boot_map = match unsafe { detach_firmware(image_handle, boot_services) } {
        Ok(map) => map,
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
    serial_write("ORYVAEL: native runtime boundary established\r\n");

    let mut frames = FrameAllocator::from_boot_map(&boot_map);
    serial_write("ORYVAEL: physical allocator online regions=");
    serial_write_u64(frames.region_count() as u64);
    serial_write(" free_pages=");
    serial_write_u64(frames.free_pages());
    serial_write("\r\n");

    let mut heap = KernelHeap::new();
    let heap_probe = heap.alloc(64, 16).unwrap_or(0);
    if heap_probe == 0 {
        serial_write("ORYVAEL: kernel heap initialization failed\r\n");
        return 2;
    }
    // SAFETY: heap_probe identifies the 64 bytes just reserved from the static
    // kernel heap and therefore can be written by the kernel.
    unsafe { core::ptr::write_bytes(heap_probe as *mut u8, 0xa5, 64) };
    serial_write("ORYVAEL: kernel heap online bytes=");
    serial_write_u64(KERNEL_HEAP_BYTES as u64);
    serial_write("\r\n");

    install_timer_interrupt_path();
    if !wait_for_timer_tick() {
        serial_write("ORYVAEL: timer interrupt self-test failed\r\n");
        return 3;
    }
    serial_write("ORYVAEL: timer interrupts online hz=");
    serial_write_u64(TIMER_HZ);
    serial_write("\r\n");

    serial_write("ORYVAEL: memory descriptors=");
    serial_write_u64(boot_map.descriptors as u64);
    serial_write(" conventional_pages=");
    serial_write_u64(boot_map.conventional_pages);
    serial_write(" reclaimable_pages=");
    serial_write_u64(boot_map.reclaimable_pages);
    serial_write(" runtime_pages=");
    serial_write_u64(boot_map.runtime_pages);
    serial_write("\r\n");

    serial_write("ORYVAEL: minimal system ready\r\n");
    kernel_console(&mut frames, &mut heap)
}

unsafe fn detach_firmware(
    image_handle: EfiHandle,
    boot_services: *mut EfiBootServices,
) -> Result<BootMemoryMap, EfiStatus> {
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
        // reference to the static mut buffer. The single boot CPU owns it.
        let map_ptr = unsafe { core::ptr::addr_of_mut!(MEMORY_MAP.0).cast::<u8>() };

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

        let summary = unsafe { summarize_memory(map_ptr, map_size, descriptor_size) };

        // SAFETY: UEFI requires the latest map key from GetMemoryMap. No UEFI
        // allocation or protocol operation occurs between these calls.
        let exit_status = unsafe { exit_boot_services(image_handle, map_key) };
        if exit_status == EFI_SUCCESS {
            return Ok(BootMemoryMap {
                map_ptr,
                map_size,
                descriptor_size,
                descriptors: summary.descriptors,
                reclaimable_pages: summary.reclaimable_pages,
                conventional_pages: summary.conventional_pages,
                runtime_pages: summary.runtime_pages,
            });
        }
    }

    Err(usize::MAX)
}

#[derive(Clone, Copy)]
struct MemorySummary {
    descriptors: usize,
    reclaimable_pages: u64,
    conventional_pages: u64,
    runtime_pages: u64,
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
            conventional_pages: 0,
            runtime_pages: 0,
        };
    }

    let mut offset = 0usize;
    let mut descriptors = 0usize;
    let mut reclaimable_pages = 0u64;
    let mut conventional_pages = 0u64;
    let mut runtime_pages = 0u64;

    while offset.saturating_add(descriptor_size) <= map_size {
        // SAFETY: offset is bounded by map_size and GetMemoryMap guarantees at
        // least descriptor_size bytes per entry.
        let descriptor = unsafe {
            core::ptr::read_unaligned(map_ptr.add(offset).cast::<EfiMemoryDescriptor>())
        };

        descriptors += 1;
        match descriptor.memory_type {
            EFI_LOADER_CODE | EFI_LOADER_DATA | EFI_BOOT_SERVICES_CODE | EFI_BOOT_SERVICES_DATA => {
                reclaimable_pages = reclaimable_pages.saturating_add(descriptor.number_of_pages);
            }
            EFI_CONVENTIONAL_MEMORY => {
                reclaimable_pages = reclaimable_pages.saturating_add(descriptor.number_of_pages);
                conventional_pages = conventional_pages.saturating_add(descriptor.number_of_pages);
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
        conventional_pages,
        runtime_pages,
    }
}

fn wait_for_timer_tick() -> bool {
    let before = timer_ticks();
    for _ in 0..50_000_000 {
        if timer_ticks() != before {
            return true;
        }
        cpu_relax();
    }
    false
}

fn install_timer_interrupt_path() {
    disable_interrupts();
    install_idt();
    remap_and_mask_pic();
    program_pit(TIMER_HZ);
    enable_interrupts();
}

fn install_idt() {
    let selector = current_code_segment();
    let handler = oryvael_timer_interrupt as *const () as u64;

    // SAFETY: interrupts are disabled; the boot CPU has exclusive access to
    // the static IDT while vector 32 is installed.
    unsafe {
        let idt_ptr = core::ptr::addr_of_mut!(IDT.0).cast::<IdtEntry>();
        core::ptr::write(idt_ptr.add(32), IdtEntry::interrupt_gate(handler, selector));
        let idtr = Idtr {
            limit: (size_of::<[IdtEntry; 256]>() - 1) as u16,
            base: idt_ptr as u64,
        };
        asm!("lidt [{}]", in(reg) &idtr, options(readonly, nostack, preserves_flags));
    }
}

fn current_code_segment() -> u16 {
    let selector: u16;
    // SAFETY: reading CS is side-effect free and supplies the selector needed
    // by x86_64 interrupt gates.
    unsafe {
        asm!("mov {0:x}, cs", out(reg) selector, options(nomem, nostack, preserves_flags));
    }
    selector
}

fn remap_and_mask_pic() {
    // SAFETY: these are the legacy 8259 PIC command/data ports on the x86_64
    // PC platform. Stage 1 unmasks only IRQ0 (the timer); all others stay
    // masked and keyboard/serial input is polled by the console loop.
    unsafe {
        outb(PIC1_COMMAND, 0x11);
        io_wait();
        outb(PIC2_COMMAND, 0x11);
        io_wait();
        outb(PIC1_DATA, 0x20);
        io_wait();
        outb(PIC2_DATA, 0x28);
        io_wait();
        outb(PIC1_DATA, 0x04);
        io_wait();
        outb(PIC2_DATA, 0x02);
        io_wait();
        outb(PIC1_DATA, 0x01);
        io_wait();
        outb(PIC2_DATA, 0x01);
        io_wait();
        outb(PIC1_DATA, 0xfe);
        outb(PIC2_DATA, 0xff);
    }
}

fn program_pit(hz: u64) {
    let divisor = (PIT_BASE_HZ / hz.max(1)).clamp(1, u16::MAX as u64) as u16;
    // SAFETY: PIT channel 0 is the Stage 1 clock source and its ports are fixed
    // by the PC-compatible x86 platform.
    unsafe {
        outb(PIT_COMMAND, 0x36);
        outb(PIT_CHANNEL0, divisor as u8);
        outb(PIT_CHANNEL0, (divisor >> 8) as u8);
    }
}

struct KeyboardState {
    shift: bool,
}

impl KeyboardState {
    const fn new() -> Self {
        Self { shift: false }
    }

    fn try_read_ascii(&mut self) -> Option<u8> {
        // SAFETY: reading the i8042 status/data ports is confined to the
        // PC-compatible keyboard controller. IRQ1 stays masked, so polling is
        // the sole consumer in Stage 1.
        let status = unsafe { inb(PS2_STATUS_COMMAND) };
        if status & 0x01 == 0 {
            return None;
        }
        let scan = unsafe { inb(PS2_DATA) };

        match scan {
            0x2a | 0x36 => {
                self.shift = true;
                None
            }
            0xaa | 0xb6 => {
                self.shift = false;
                None
            }
            _ if scan & 0x80 != 0 => None,
            _ => translate_scancode(scan, self.shift),
        }
    }
}

fn translate_scancode(scan: u8, shift: bool) -> Option<u8> {
    let byte = match scan {
        0x01 => 0x1b,
        0x02 => if shift { b'!' } else { b'1' },
        0x03 => if shift { b'@' } else { b'2' },
        0x04 => if shift { b'#' } else { b'3' },
        0x05 => if shift { b'$' } else { b'4' },
        0x06 => if shift { b'%' } else { b'5' },
        0x07 => if shift { b'^' } else { b'6' },
        0x08 => if shift { b'&' } else { b'7' },
        0x09 => if shift { b'*' } else { b'8' },
        0x0a => if shift { b'(' } else { b'9' },
        0x0b => if shift { b')' } else { b'0' },
        0x0e => 0x08,
        0x0f => b' ',
        0x10 => letter(b'q', shift),
        0x11 => letter(b'w', shift),
        0x12 => letter(b'e', shift),
        0x13 => letter(b'r', shift),
        0x14 => letter(b't', shift),
        0x15 => letter(b'y', shift),
        0x16 => letter(b'u', shift),
        0x17 => letter(b'i', shift),
        0x18 => letter(b'o', shift),
        0x19 => letter(b'p', shift),
        0x1c => b'\r',
        0x1e => letter(b'a', shift),
        0x1f => letter(b's', shift),
        0x20 => letter(b'd', shift),
        0x21 => letter(b'f', shift),
        0x22 => letter(b'g', shift),
        0x23 => letter(b'h', shift),
        0x24 => letter(b'j', shift),
        0x25 => letter(b'k', shift),
        0x26 => letter(b'l', shift),
        0x2c => letter(b'z', shift),
        0x2d => letter(b'x', shift),
        0x2e => letter(b'c', shift),
        0x2f => letter(b'v', shift),
        0x30 => letter(b'b', shift),
        0x31 => letter(b'n', shift),
        0x32 => letter(b'm', shift),
        0x39 => b' ',
        _ => return None,
    };
    Some(byte)
}

fn letter(lower: u8, shift: bool) -> u8 {
    if shift { lower - 32 } else { lower }
}

fn kernel_console(frames: &mut FrameAllocator, heap: &mut KernelHeap) -> ! {
    serial_write("\r\nORYVAEL OS minimal base\r\n");
    serial_write("bare-metal x86_64 | 100 Hz kernel timer | serial + PS/2 console\r\n");
    serial_write("type 'help' for commands\r\n\r\n");

    let mut keyboard = KeyboardState::new();
    let mut line = [0u8; 128];
    let mut length = 0usize;
    let mut last_was_cr = false;
    prompt();

    loop {
        let byte = serial_try_read().or_else(|| keyboard.try_read_ascii());
        match byte {
            Some(b'\r') => {
                serial_write("\r\n");
                execute_command(&line[..length], frames, heap);
                length = 0;
                last_was_cr = true;
                prompt();
            }
            Some(b'\n') if last_was_cr => {
                last_was_cr = false;
            }
            Some(b'\n') => {
                serial_write("\r\n");
                execute_command(&line[..length], frames, heap);
                length = 0;
                prompt();
            }
            Some(0x08 | 0x7f) => {
                last_was_cr = false;
                if length != 0 {
                    length -= 1;
                    serial_write("\x08 \x08");
                }
            }
            Some(byte) if (0x20..=0x7e).contains(&byte) => {
                last_was_cr = false;
                if length < line.len() {
                    line[length] = byte;
                    length += 1;
                    serial_write_byte(byte);
                }
            }
            Some(_) => {
                last_was_cr = false;
            }
            None => cpu_relax(),
        }
    }
}

fn execute_command(line: &[u8], frames: &mut FrameAllocator, heap: &mut KernelHeap) {
    let command = trim_ascii(line);
    if command.is_empty() {
        return;
    }

    if command == b"help" {
        serial_write("commands: help mem uptime alloc clear about reboot\r\n");
    } else if command == b"mem" {
        serial_write("memory: conventional_free_pages=");
        serial_write_u64(frames.free_pages());
        serial_write(" free_mib=");
        serial_write_u64(frames.free_pages().saturating_mul(PAGE_SIZE) / (1024 * 1024));
        serial_write(" heap_used=");
        serial_write_u64(heap.used() as u64);
        serial_write(" heap_free=");
        serial_write_u64(heap.free() as u64);
        serial_write("\r\n");
    } else if command == b"uptime" {
        let ticks = timer_ticks();
        serial_write("uptime: ticks=");
        serial_write_u64(ticks);
        serial_write(" seconds=");
        serial_write_u64(ticks / TIMER_HZ);
        serial_write("\r\n");
    } else if command == b"alloc" {
        serial_write("alloc: frame=");
        match frames.alloc_frame() {
            Some(frame) => serial_write_hex(frame),
            None => serial_write("none"),
        }
        serial_write(" heap64=");
        match heap.alloc(64, 16) {
            Some(address) => serial_write_hex(address as u64),
            None => serial_write("none"),
        }
        serial_write("\r\n");
    } else if command == b"clear" {
        serial_write("\x1b[2J\x1b[H");
    } else if command == b"about" {
        serial_write("ORYVAEL native system: capability-first authority under human control\r\n");
    } else if command == b"reboot" {
        serial_write("rebooting...\r\n");
        reboot();
    } else {
        serial_write("unknown command: ");
        for &byte in command {
            serial_write_byte(byte);
        }
        serial_write("\r\n");
    }
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while bytes.first() == Some(&b' ') || bytes.first() == Some(&b'\t') {
        bytes = &bytes[1..];
    }
    while bytes.last() == Some(&b' ') || bytes.last() == Some(&b'\t') {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn prompt() {
    serial_write("oryvael> ");
}

fn timer_ticks() -> u64 {
    // SAFETY: the timer ISR is the only writer and aligned u64 loads are atomic
    // on x86_64. volatile prevents the compiler from caching the value.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ORYVAEL_TICKS)) }
}

fn serial_init() {
    // SAFETY: COM1 is the legacy x86_64 UART I/O range.
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

fn serial_try_read() -> Option<u8> {
    // SAFETY: COM1 line-status and data ports are fixed x86 I/O ports.
    unsafe {
        if inb(COM1 + 5) & 0x01 != 0 {
            Some(inb(COM1))
        } else {
            None
        }
    }
}

fn serial_write(text: &str) {
    for byte in text.bytes() {
        serial_write_byte(byte);
    }
}

fn serial_write_byte(byte: u8) {
    for _ in 0..100_000 {
        // SAFETY: reading the UART line-status register is confined to COM1.
        if unsafe { inb(COM1 + 5) } & 0x20 != 0 {
            break;
        }
        core::hint::spin_loop();
    }
    // SAFETY: writing COM1 transmits one diagnostic/console byte.
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
    // SAFETY: Stage 1 controls interrupt enable/disable around IDT/PIC setup.
    unsafe { asm!("cli", options(nomem, nostack)) };
}

fn enable_interrupts() {
    // SAFETY: called only after vector 32, PIC and PIT are configured.
    unsafe { asm!("sti", options(nomem, nostack)) };
}

fn cpu_relax() {
    core::hint::spin_loop();
}

fn reboot() -> ! {
    disable_interrupts();
    // Wait until the i8042 input buffer is clear, then request a CPU reset.
    for _ in 0..100_000 {
        // SAFETY: i8042 status port is fixed on PC-compatible x86 hardware.
        if unsafe { inb(PS2_STATUS_COMMAND) } & 0x02 == 0 {
            break;
        }
        core::hint::spin_loop();
    }
    // SAFETY: command 0xfe asks the i8042-compatible controller to pulse reset.
    unsafe { outb(PS2_STATUS_COMMAND, 0xfe) };
    loop {
        // SAFETY: if reset is delayed, remain halted with interrupts disabled.
        unsafe { asm!("hlt", options(nomem, nostack)) };
    }
}

fn align_up_u64(value: u64, alignment: u64) -> u64 {
    value
        .saturating_add(alignment - 1)
        .checked_div(alignment)
        .unwrap_or(0)
        .saturating_mul(alignment)
}

fn align_down_u64(value: u64, alignment: u64) -> u64 {
    value / alignment * alignment
}

fn align_up_usize(value: usize, alignment: usize) -> Option<usize> {
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
}

unsafe fn io_wait() {
    // SAFETY: port 0x80 is the conventional PC POST delay port.
    unsafe { outb(0x80, 0) };
}

unsafe fn outb(port: u16, value: u8) {
    // SAFETY: caller selects a valid x86 I/O port.
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
    // SAFETY: caller selects a valid x86 I/O port.
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
    disable_interrupts();
    serial_init();
    serial_write("\r\nORYVAEL: KERNEL PANIC\r\n");
    loop {
        // SAFETY: panic is terminal in the current kernel stage.
        unsafe { asm!("hlt", options(nomem, nostack)) };
    }
}
