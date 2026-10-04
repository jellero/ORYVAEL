use core::arch::asm;
use core::mem::size_of;

use crate::boot::{BootMemoryMap, EfiMemoryDescriptor, EFI_CONVENTIONAL_MEMORY};

pub const PAGE_SIZE: u64 = 4096;
const LOW_MEMORY_CUTOFF: u64 = 0x10_0000;
const MAX_FRAME_REGIONS: usize = 64;
const KERNEL_HEAP_BYTES: usize = 256 * 1024;
const PAGE_TABLE_POOL_PAGES: usize = 8;

const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITABLE: u64 = 1 << 1;
const PTE_USER: u64 = 1 << 2;
const PTE_HUGE: u64 = 1 << 7;
const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;

#[derive(Clone, Copy)]
struct FrameRegion {
    next: u64,
    end: u64,
}

const EMPTY_FRAME_REGION: FrameRegion = FrameRegion { next: 0, end: 0 };

pub struct FrameAllocator {
    regions: [FrameRegion; MAX_FRAME_REGIONS],
    region_count: usize,
    cursor: usize,
    free_pages: u64,
}

impl FrameAllocator {
    pub fn from_boot_map(map: &BootMemoryMap) -> Self {
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
            // SAFETY: the retained firmware map is immutable after ExitBootServices.
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
                    allocator.regions[allocator.region_count] = FrameRegion { next: start, end };
                    allocator.region_count += 1;
                    allocator.free_pages = allocator
                        .free_pages
                        .saturating_add((end - start) / PAGE_SIZE);
                }
            }
            offset += map.descriptor_size;
        }
        allocator
    }

    pub fn alloc_frame(&mut self) -> Option<u64> {
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

    pub fn free_pages(&self) -> u64 {
        self.free_pages
    }

    pub fn region_count(&self) -> usize {
        self.region_count
    }
}

#[repr(align(64))]
struct HeapStorage([u8; KERNEL_HEAP_BYTES]);

static mut KERNEL_HEAP_STORAGE: HeapStorage = HeapStorage([0; KERNEL_HEAP_BYTES]);

pub struct KernelHeap {
    start: usize,
    next: usize,
    end: usize,
}

impl KernelHeap {
    pub fn new() -> Self {
        // SAFETY: the single boot CPU exclusively owns this storage.
        let start = unsafe { core::ptr::addr_of_mut!(KERNEL_HEAP_STORAGE.0).cast::<u8>() as usize };
        Self {
            start,
            next: start,
            end: start + KERNEL_HEAP_BYTES,
        }
    }

    pub fn alloc(&mut self, bytes: usize, alignment: usize) -> Option<usize> {
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

    pub fn used(&self) -> usize {
        self.next - self.start
    }

    pub fn free(&self) -> usize {
        self.end - self.next
    }

    pub fn capacity(&self) -> usize {
        KERNEL_HEAP_BYTES
    }
}

#[repr(C, align(4096))]
#[derive(Clone, Copy)]
struct TablePage([u64; 512]);

const EMPTY_TABLE_PAGE: TablePage = TablePage([0; 512]);
static mut PAGE_TABLE_POOL: [TablePage; PAGE_TABLE_POOL_PAGES] =
    [EMPTY_TABLE_PAGE; PAGE_TABLE_POOL_PAGES];

pub struct PageTables {
    root_phys: u64,
    pool_phys: [u64; PAGE_TABLE_POOL_PAGES],
    next_table: usize,
}

impl PageTables {
    pub fn take_ownership() -> Option<Self> {
        let old_root = read_cr3() & ADDRESS_MASK;
        let mut pool_phys = [0u64; PAGE_TABLE_POOL_PAGES];

        for (index, slot) in pool_phys.iter_mut().enumerate() {
            let va = table_page_ptr(index) as u64;
            *slot = translate_with_root(old_root, va)? & ADDRESS_MASK;
        }

        let new_root_ptr = table_page_ptr(0);
        // SAFETY: under the x86_64 UEFI handoff used by this target, page-table
        // frames are directly addressable in the inherited identity window.
        // We copy the top level once, then switch CR3 to ORYVAEL-owned storage.
        unsafe {
            core::ptr::copy_nonoverlapping(old_root as *const u64, new_root_ptr, 512);
        }
        let new_root = pool_phys[0];
        // SAFETY: new_root points at an aligned PML4 containing the live mappings.
        unsafe { write_cr3(new_root) };

        Some(Self {
            root_phys: new_root,
            pool_phys,
            next_table: 1,
        })
    }

    pub fn root_phys(&self) -> u64 {
        self.root_phys
    }

    pub fn translate_kernel_va(&self, va: u64) -> Option<u64> {
        translate_with_root(self.root_phys, va)
    }

    pub fn install_user_triplet(
        &mut self,
        code_va: u64,
        code_backing_va: u64,
        data_va: u64,
        data_backing_va: u64,
        stack_va: u64,
        stack_backing_va: u64,
    ) -> Option<()> {
        let code_indices = page_indices(code_va);
        let data_indices = page_indices(data_va);
        let stack_indices = page_indices(stack_va);
        if code_indices[..3] != data_indices[..3]
            || code_indices[..3] != stack_indices[..3]
        {
            return None;
        }

        let root = table_page_ptr(0);
        // The chosen user slot must be fresh; ORYVAEL never broadens an inherited
        // supervisor mapping into user space.
        unsafe {
            if core::ptr::read(root.add(code_indices[0])) & PTE_PRESENT != 0 {
                return None;
            }
        }

        let pdpt_index = self.alloc_table()?;
        let pd_index = self.alloc_table()?;
        let pt_index = self.alloc_table()?;
        let pdpt = table_page_ptr(pdpt_index);
        let pd = table_page_ptr(pd_index);
        let pt = table_page_ptr(pt_index);
        let branch_flags = PTE_PRESENT | PTE_WRITABLE | PTE_USER;

        unsafe {
            core::ptr::write(
                root.add(code_indices[0]),
                self.pool_phys[pdpt_index] | branch_flags,
            );
            core::ptr::write(
                pdpt.add(code_indices[1]),
                self.pool_phys[pd_index] | branch_flags,
            );
            core::ptr::write(
                pd.add(code_indices[2]),
                self.pool_phys[pt_index] | branch_flags,
            );
        }

        let code_phys = self.translate_kernel_va(code_backing_va)? & ADDRESS_MASK;
        let data_phys = self.translate_kernel_va(data_backing_va)? & ADDRESS_MASK;
        let stack_phys = self.translate_kernel_va(stack_backing_va)? & ADDRESS_MASK;
        unsafe {
            core::ptr::write(
                pt.add(code_indices[3]),
                code_phys | PTE_PRESENT | PTE_USER,
            );
            core::ptr::write(
                pt.add(data_indices[3]),
                data_phys | PTE_PRESENT | PTE_WRITABLE | PTE_USER,
            );
            core::ptr::write(
                pt.add(stack_indices[3]),
                stack_phys | PTE_PRESENT | PTE_WRITABLE | PTE_USER,
            );
            asm!("invlpg [{}]", in(reg) code_va, options(nostack, preserves_flags));
            asm!("invlpg [{}]", in(reg) data_va, options(nostack, preserves_flags));
            asm!("invlpg [{}]", in(reg) stack_va, options(nostack, preserves_flags));
        }
        Some(())
    }

    fn alloc_table(&mut self) -> Option<usize> {
        if self.next_table >= PAGE_TABLE_POOL_PAGES {
            return None;
        }
        let index = self.next_table;
        self.next_table += 1;
        let ptr = table_page_ptr(index);
        // SAFETY: this page belongs exclusively to the page-table pool.
        unsafe { core::ptr::write_bytes(ptr.cast::<u8>(), 0, PAGE_SIZE as usize) };
        Some(index)
    }
}

fn table_page_ptr(index: usize) -> *mut u64 {
    // SAFETY: callers bound index by PAGE_TABLE_POOL_PAGES and never create a
    // Rust reference to the mutable static.
    unsafe {
        core::ptr::addr_of_mut!(PAGE_TABLE_POOL)
            .cast::<TablePage>()
            .add(index)
            .cast::<u64>()
    }
}

fn page_indices(va: u64) -> [usize; 4] {
    [
        ((va >> 39) & 0x1ff) as usize,
        ((va >> 30) & 0x1ff) as usize,
        ((va >> 21) & 0x1ff) as usize,
        ((va >> 12) & 0x1ff) as usize,
    ]
}

fn translate_with_root(root_phys: u64, va: u64) -> Option<u64> {
    // Stage-2 x86_64 uses the UEFI identity window while replacing the PML4.
    // Lower mappings are migrated incrementally; huge inherited mappings are
    // understood so kernel/static storage remains addressable during the move.
    unsafe {
        let pml4 = root_phys as *const u64;
        let e1 = core::ptr::read(pml4.add(((va >> 39) & 0x1ff) as usize));
        if e1 & PTE_PRESENT == 0 {
            return None;
        }
        let pdpt = (e1 & ADDRESS_MASK) as *const u64;
        let e2 = core::ptr::read(pdpt.add(((va >> 30) & 0x1ff) as usize));
        if e2 & PTE_PRESENT == 0 {
            return None;
        }
        if e2 & PTE_HUGE != 0 {
            let base = e2 & 0x000f_ffff_c000_0000;
            return Some(base | (va & 0x3fff_ffff));
        }
        let pd = (e2 & ADDRESS_MASK) as *const u64;
        let e3 = core::ptr::read(pd.add(((va >> 21) & 0x1ff) as usize));
        if e3 & PTE_PRESENT == 0 {
            return None;
        }
        if e3 & PTE_HUGE != 0 {
            let base = e3 & 0x000f_ffff_ffe0_0000;
            return Some(base | (va & 0x1f_ffff));
        }
        let pt = (e3 & ADDRESS_MASK) as *const u64;
        let e4 = core::ptr::read(pt.add(((va >> 12) & 0x1ff) as usize));
        if e4 & PTE_PRESENT == 0 {
            return None;
        }
        Some((e4 & ADDRESS_MASK) | (va & 0xfff))
    }
}

fn read_cr3() -> u64 {
    let value: u64;
    // SAFETY: reading CR3 is side-effect free at CPL0.
    unsafe { asm!("mov {}, cr3", out(reg) value, options(nomem, nostack, preserves_flags)) };
    value
}

unsafe fn write_cr3(value: u64) {
    // SAFETY: caller guarantees a valid aligned PML4 physical address.
    unsafe { asm!("mov cr3, {}", in(reg) value, options(nostack, preserves_flags)) };
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
