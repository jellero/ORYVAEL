use core::ffi::c_void;
use core::mem::size_of;

pub type EfiStatus = usize;
pub type EfiHandle = *mut c_void;

const EFI_SUCCESS: EfiStatus = 0;
const MEMORY_MAP_CAPACITY: usize = 128 * 1024;
const PAGE_SIZE: usize = 4096;
const MAX_GRAPHICS_BACKBUFFER_BYTES: usize = 32 * 1024 * 1024;

const EFI_ALLOCATE_ANY_PAGES: u32 = 0;
const EFI_LOADER_CODE: u32 = 1;
const EFI_LOADER_DATA: u32 = 2;
const EFI_BOOT_SERVICES_CODE: u32 = 3;
const EFI_BOOT_SERVICES_DATA: u32 = 4;
const EFI_RUNTIME_SERVICES_CODE: u32 = 5;
const EFI_RUNTIME_SERVICES_DATA: u32 = 6;
pub const EFI_CONVENTIONAL_MEMORY: u32 = 7;

const GOP_GUID: EfiGuid = EfiGuid {
    data1: 0x9042_a9de,
    data2: 0x23dc,
    data3: 0x4a38,
    data4: [0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a],
};

#[repr(C)]
struct EfiGuid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[repr(C)]
struct EfiTableHeader {
    signature: u64,
    revision: u32,
    header_size: u32,
    crc32: u32,
    reserved: u32,
}

type EfiAllocatePages = unsafe extern "efiapi" fn(
    allocate_type: u32,
    memory_type: u32,
    pages: usize,
    memory: *mut u64,
) -> EfiStatus;

type EfiGetMemoryMap = unsafe extern "efiapi" fn(
    memory_map_size: *mut usize,
    memory_map: *mut EfiMemoryDescriptor,
    map_key: *mut usize,
    descriptor_size: *mut usize,
    descriptor_version: *mut u32,
) -> EfiStatus;

type EfiHandleProtocol = unsafe extern "efiapi" fn(
    handle: EfiHandle,
    protocol: *const EfiGuid,
    interface: *mut *mut c_void,
) -> EfiStatus;

type EfiExitBootServices =
    unsafe extern "efiapi" fn(image_handle: EfiHandle, map_key: usize) -> EfiStatus;

type EfiLocateProtocol = unsafe extern "efiapi" fn(
    protocol: *const EfiGuid,
    registration: *mut c_void,
    interface: *mut *mut c_void,
) -> EfiStatus;

#[repr(C)]
struct EfiBootServices {
    header: EfiTableHeader,
    raise_tpl: usize,
    restore_tpl: usize,
    allocate_pages: EfiAllocatePages,
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
    handle_protocol: EfiHandleProtocol,
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
    get_next_monotonic_count: usize,
    stall: usize,
    set_watchdog_timer: usize,
    connect_controller: usize,
    disconnect_controller: usize,
    open_protocol: usize,
    close_protocol: usize,
    open_protocol_information: usize,
    protocols_per_handle: usize,
    locate_handle_buffer: usize,
    locate_protocol: EfiLocateProtocol,
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
struct EfiPixelBitmask {
    red_mask: u32,
    green_mask: u32,
    blue_mask: u32,
    reserved_mask: u32,
}

#[repr(C)]
struct EfiGraphicsOutputModeInformation {
    version: u32,
    horizontal_resolution: u32,
    vertical_resolution: u32,
    pixel_format: u32,
    pixel_information: EfiPixelBitmask,
    pixels_per_scan_line: u32,
}

#[repr(C)]
struct EfiGraphicsOutputProtocolMode {
    max_mode: u32,
    mode: u32,
    info: *mut EfiGraphicsOutputModeInformation,
    size_of_info: usize,
    frame_buffer_base: u64,
    frame_buffer_size: usize,
}

#[repr(C)]
struct EfiGraphicsOutputProtocol {
    query_mode: usize,
    set_mode: usize,
    blt: usize,
    mode: *mut EfiGraphicsOutputProtocolMode,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EfiMemoryDescriptor {
    pub memory_type: u32,
    _padding: u32,
    pub physical_start: u64,
    virtual_start: u64,
    pub number_of_pages: u64,
    attribute: u64,
}

#[repr(align(16))]
struct AlignedMemoryMap([u8; MEMORY_MAP_CAPACITY]);

static mut MEMORY_MAP: AlignedMemoryMap = AlignedMemoryMap([0; MEMORY_MAP_CAPACITY]);

#[derive(Clone, Copy)]
pub struct BootGraphics {
    pub framebuffer_base: u64,
    pub framebuffer_size: usize,
    pub backbuffer_base: u64,
    pub backbuffer_size: usize,
    pub width: u32,
    pub height: u32,
    pub pixels_per_scan_line: u32,
    pub pixel_format: u32,
}

#[derive(Clone, Copy)]
pub struct BootMemoryMap {
    pub map_ptr: *const u8,
    pub map_size: usize,
    pub descriptor_size: usize,
    pub descriptors: usize,
    pub reclaimable_pages: u64,
    pub conventional_pages: u64,
    pub runtime_pages: u64,
}

#[derive(Clone, Copy)]
struct MemorySummary {
    descriptors: usize,
    reclaimable_pages: u64,
    conventional_pages: u64,
    runtime_pages: u64,
}

pub unsafe fn boot_services_from_system_table(system_table: *mut c_void) -> Option<*mut c_void> {
    if system_table.is_null() {
        return None;
    }
    let table = system_table.cast::<EfiSystemTable>();
    // SAFETY: UEFI supplies a valid EFI_SYSTEM_TABLE until ExitBootServices.
    let services = unsafe { (*table).boot_services };
    if services.is_null() {
        None
    } else {
        Some(services.cast::<c_void>())
    }
}

pub unsafe fn prepare_graphics(system_table: *mut c_void) -> Option<BootGraphics> {
    if system_table.is_null() {
        return None;
    }

    let table = system_table.cast::<EfiSystemTable>();
    // SAFETY: system_table is owned by firmware until ExitBootServices.
    let boot_services = unsafe { (*table).boot_services };
    // SAFETY: same firmware-owned table lifetime.
    let console_out_handle = unsafe { (*table).console_out_handle };
    if boot_services.is_null() || console_out_handle.is_null() {
        return None;
    }

    let mut interface = core::ptr::null_mut::<c_void>();
    // Prefer LocateProtocol because the GOP device handle does not have to be
    // identical to the system-table ConsoleOut handle.
    let locate_protocol = unsafe { (*boot_services).locate_protocol };
    let mut status = unsafe {
        locate_protocol(&GOP_GUID, core::ptr::null_mut(), &mut interface)
    };
    if status != EFI_SUCCESS || interface.is_null() {
        // Some firmware exposes GOP directly on ConsoleOut; keep this as a
        // conservative fallback for simple implementations.
        let handle_protocol = unsafe { (*boot_services).handle_protocol };
        interface = core::ptr::null_mut();
        status = unsafe { handle_protocol(console_out_handle, &GOP_GUID, &mut interface) };
    }
    if status != EFI_SUCCESS || interface.is_null() {
        return None;
    }

    let gop = interface.cast::<EfiGraphicsOutputProtocol>();
    // SAFETY: a successful GOP lookup returns a valid protocol object.
    let mode = unsafe { (*gop).mode };
    if mode.is_null() {
        return None;
    }
    // SAFETY: mode is owned by the live GOP instance.
    let info = unsafe { (*mode).info };
    if info.is_null() {
        return None;
    }

    // Only the two standard 32-bit packed pixel formats are accepted by the
    // first native renderer. PixelBitMask and BltOnly remain future work.
    let pixel_format = unsafe { (*info).pixel_format };
    if pixel_format > 1 {
        return None;
    }

    let framebuffer_base = unsafe { (*mode).frame_buffer_base };
    let framebuffer_size = unsafe { (*mode).frame_buffer_size };
    let width = unsafe { (*info).horizontal_resolution };
    let height = unsafe { (*info).vertical_resolution };
    let pixels_per_scan_line = unsafe { (*info).pixels_per_scan_line };
    if framebuffer_base == 0
        || framebuffer_size == 0
        || width == 0
        || height == 0
        || pixels_per_scan_line < width
    {
        return None;
    }

    let required_bytes = (pixels_per_scan_line as usize)
        .checked_mul(height as usize)?
        .checked_mul(4)?;
    if required_bytes > framebuffer_size {
        return None;
    }

    let mut backbuffer_base = 0u64;
    let mut backbuffer_size = 0usize;
    if required_bytes <= MAX_GRAPHICS_BACKBUFFER_BYTES {
        let pages = required_bytes.checked_add(PAGE_SIZE - 1)? / PAGE_SIZE;
        if pages != 0 {
            // SAFETY: firmware allocates page-aligned LoaderData before the final
            // memory map is captured. ORYVAEL's frame allocator later consumes
            // only ConventionalMemory, so this reservation remains exclusive.
            let allocate_pages = unsafe { (*boot_services).allocate_pages };
            let alloc_status = unsafe {
                allocate_pages(
                    EFI_ALLOCATE_ANY_PAGES,
                    EFI_LOADER_DATA,
                    pages,
                    &mut backbuffer_base,
                )
            };
            if alloc_status == EFI_SUCCESS {
                backbuffer_size = pages.saturating_mul(PAGE_SIZE);
            } else {
                backbuffer_base = 0;
            }
        }
    }

    Some(BootGraphics {
        framebuffer_base,
        framebuffer_size,
        backbuffer_base,
        backbuffer_size,
        width,
        height,
        pixels_per_scan_line,
        pixel_format,
    })
}

pub unsafe fn detach_firmware(
    image_handle: EfiHandle,
    boot_services: *mut c_void,
) -> Result<BootMemoryMap, EfiStatus> {
    let boot_services = boot_services.cast::<EfiBootServices>();
    // SAFETY: caller obtained this table from the live UEFI system table.
    let get_memory_map = unsafe { (*boot_services).get_memory_map };
    // SAFETY: same table and lifetime as above.
    let exit_boot_services = unsafe { (*boot_services).exit_boot_services };

    for _ in 0..4 {
        let mut map_size = MEMORY_MAP_CAPACITY;
        let mut map_key = 0usize;
        let mut descriptor_size = 0usize;
        let mut descriptor_version = 0u32;
        // SAFETY: single boot CPU exclusively owns the retained static buffer.
        let map_ptr = unsafe { core::ptr::addr_of_mut!(MEMORY_MAP.0).cast::<u8>() };

        // SAFETY: all pointers address writable storage for the UEFI outputs.
        let status = unsafe {
            get_memory_map(
                &mut map_size,
                map_ptr.cast::<EfiMemoryDescriptor>(),
                &mut map_key,
                &mut descriptor_size,
                &mut descriptor_version,
            )
        };
        if status != EFI_SUCCESS {
            return Err(status);
        }

        let summary = unsafe { summarize_memory(map_ptr, map_size, descriptor_size) };
        // SAFETY: no allocation/protocol operation occurs after the final map.
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
    let mut summary = MemorySummary {
        descriptors: 0,
        reclaimable_pages: 0,
        conventional_pages: 0,
        runtime_pages: 0,
    };

    while offset.saturating_add(descriptor_size) <= map_size {
        // SAFETY: GetMemoryMap populated at least descriptor_size bytes here.
        let descriptor = unsafe {
            core::ptr::read_unaligned(map_ptr.add(offset).cast::<EfiMemoryDescriptor>())
        };
        summary.descriptors += 1;
        match descriptor.memory_type {
            EFI_LOADER_CODE | EFI_LOADER_DATA | EFI_BOOT_SERVICES_CODE | EFI_BOOT_SERVICES_DATA => {
                summary.reclaimable_pages = summary
                    .reclaimable_pages
                    .saturating_add(descriptor.number_of_pages);
            }
            EFI_CONVENTIONAL_MEMORY => {
                summary.reclaimable_pages = summary
                    .reclaimable_pages
                    .saturating_add(descriptor.number_of_pages);
                summary.conventional_pages = summary
                    .conventional_pages
                    .saturating_add(descriptor.number_of_pages);
            }
            EFI_RUNTIME_SERVICES_CODE | EFI_RUNTIME_SERVICES_DATA => {
                summary.runtime_pages = summary
                    .runtime_pages
                    .saturating_add(descriptor.number_of_pages);
            }
            _ => {}
        }
        offset += descriptor_size;
    }

    summary
}
