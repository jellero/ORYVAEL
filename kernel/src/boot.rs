use core::ffi::c_void;
use core::mem::size_of;

pub type EfiStatus = usize;
pub type EfiHandle = *mut c_void;

const EFI_SUCCESS: EfiStatus = 0;
const MEMORY_MAP_CAPACITY: usize = 128 * 1024;

const EFI_LOADER_CODE: u32 = 1;
const EFI_LOADER_DATA: u32 = 2;
const EFI_BOOT_SERVICES_CODE: u32 = 3;
const EFI_BOOT_SERVICES_DATA: u32 = 4;
const EFI_RUNTIME_SERVICES_CODE: u32 = 5;
const EFI_RUNTIME_SERVICES_DATA: u32 = 6;
pub const EFI_CONVENTIONAL_MEMORY: u32 = 7;

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
