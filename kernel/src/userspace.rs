use crate::arch;
use crate::io;
use crate::memory::PageTables;

pub const USER_CODE_VA: u64 = 0x0000_4000_0000_0000;
pub const USER_DATA_VA: u64 = USER_CODE_VA + 0x1000;
pub const USER_STACK_VA: u64 = USER_CODE_VA + 0x2000;
const USER_STACK_TOP: u64 = USER_STACK_VA + 0x1000 - 16;
const USER_PAGE_BYTES: usize = 4096;

const SYS_EXIT: u64 = 0;
const SYS_WRITE: u64 = 1;
const SYS_TICKS: u64 = 2;
const SYS_CAP_SEND: u64 = 3;
const SYS_CAP_RECV: u64 = 4;
const SYS_FS_READ: u64 = 5;

const IPC_CAP: u64 = 0x1001;
const RAMFS_CAP: u64 = 0x2001;
const IPC_TEST_VALUE: u64 = 42;
const USER_SPIN_COUNT: u32 = 50_000_000;

static RAMFS_HELLO: &[u8] = b"hello from ORYVAEL ramfs\n";
static INIT_MESSAGE: &[u8] = b"ORYVAEL: ring3 init online\n";

#[repr(align(4096))]
struct UserPage([u8; USER_PAGE_BYTES]);

static mut USER_CODE_BACKING: UserPage = UserPage([0; USER_PAGE_BYTES]);
static mut USER_DATA_BACKING: UserPage = UserPage([0; USER_PAGE_BYTES]);
static mut USER_STACK_BACKING: UserPage = UserPage([0; USER_PAGE_BYTES]);

static mut USER_EXIT_CODE: u64 = u64::MAX;
static mut IPC_MAILBOX_VALUE: u64 = 0;
static mut IPC_MAILBOX_FULL: u8 = 0;

#[repr(C)]
pub struct UserTrapFrame {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rbp: u64,
    rdi: u64,
    rsi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
}

pub struct UserRunResult {
    pub exit_code: u64,
    pub preemptions: u64,
}

pub fn prepare_and_run(page_tables: &mut PageTables) -> Option<UserRunResult> {
    let code_va = unsafe { core::ptr::addr_of_mut!(USER_CODE_BACKING.0).cast::<u8>() as u64 };
    let data_va = unsafe { core::ptr::addr_of_mut!(USER_DATA_BACKING.0).cast::<u8>() as u64 };
    let stack_va = unsafe { core::ptr::addr_of_mut!(USER_STACK_BACKING.0).cast::<u8>() as u64 };

    // SAFETY: boot CPU exclusively owns the three user backing pages before launch.
    unsafe {
        core::ptr::write_bytes(code_va as *mut u8, 0, USER_PAGE_BYTES);
        core::ptr::write_bytes(data_va as *mut u8, 0, USER_PAGE_BYTES);
        core::ptr::write_bytes(stack_va as *mut u8, 0, USER_PAGE_BYTES);
        core::ptr::copy_nonoverlapping(
            INIT_MESSAGE.as_ptr(),
            data_va as *mut u8,
            INIT_MESSAGE.len(),
        );
    }

    build_init_program(code_va as *mut u8)?;
    page_tables.install_user_triplet(
        USER_CODE_VA,
        code_va,
        USER_DATA_VA,
        data_va,
        USER_STACK_VA,
        stack_va,
    )?;

    io::serial_write("ORYVAEL: userspace mappings online base=");
    io::serial_write_hex(USER_CODE_VA);
    io::serial_write("\r\n");
    io::serial_write("ORYVAEL: syscall console online vector=0x80\r\n");
    io::serial_write("ORYVAEL: userspace init entering ring3\r\n");

    // SAFETY: code/data/stack are user-mapped and the TSS/IDT are already live.
    unsafe { arch::enter_user(USER_CODE_VA, USER_STACK_TOP) };
    io::enable_interrupts();

    let exit_code = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(USER_EXIT_CODE)) };
    let preemptions = arch::user_preemptions();
    io::serial_write("ORYVAEL: init exited code=");
    io::serial_write_u64(exit_code);
    io::serial_write(" preemptions=");
    io::serial_write_u64(preemptions);
    io::serial_write("\r\n");

    Some(UserRunResult {
        exit_code,
        preemptions,
    })
}

fn build_init_program(code_ptr: *mut u8) -> Option<()> {
    let mut e = Emitter::new(code_ptr, USER_PAGE_BYTES);

    // Stay in ring 3 long enough for the timer to preempt this process at least
    // once. This is the scheduler/preemption smoke boundary, not a delay API.
    e.byte(0xb9)?;
    e.u32(USER_SPIN_COUNT)?;
    e.bytes(&[0xf3, 0x90, 0xff, 0xc9, 0x75, 0xfa])?; // pause; dec ecx; jnz -6

    e.syscall3(
        SYS_WRITE,
        USER_DATA_VA,
        INIT_MESSAGE.len() as u64,
        0,
    )?;
    e.syscall3(SYS_CAP_SEND, IPC_CAP, IPC_TEST_VALUE, 0)?;
    e.syscall3(SYS_CAP_RECV, IPC_CAP, 0, 0)?;

    let fs_dest = USER_DATA_VA + 512;
    e.syscall3(SYS_FS_READ, RAMFS_CAP, fs_dest, 512)?;
    // fs_read returned its byte count in rax. Move it to rsi for write().
    e.bytes(&[0x48, 0x89, 0xc6])?; // mov rsi, rax
    e.mov_rax(SYS_WRITE)?;
    e.mov_rdi(fs_dest)?;
    e.int80()?;

    e.syscall3(SYS_TICKS, 0, 0, 0)?;
    e.syscall3(SYS_EXIT, 0, 0, 0)?;
    e.bytes(&[0xf4, 0xeb, 0xfd])?; // unreachable: hlt; jmp -3
    Some(())
}

struct Emitter {
    ptr: *mut u8,
    pos: usize,
    capacity: usize,
}

impl Emitter {
    fn new(ptr: *mut u8, capacity: usize) -> Self {
        Self {
            ptr,
            pos: 0,
            capacity,
        }
    }

    fn byte(&mut self, value: u8) -> Option<()> {
        if self.pos >= self.capacity {
            return None;
        }
        // SAFETY: pos is checked against the single owned code page.
        unsafe { core::ptr::write(self.ptr.add(self.pos), value) };
        self.pos += 1;
        Some(())
    }

    fn bytes(&mut self, bytes: &[u8]) -> Option<()> {
        if self.pos.checked_add(bytes.len())? > self.capacity {
            return None;
        }
        // SAFETY: the destination range is checked and does not overlap source.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.ptr.add(self.pos), bytes.len())
        };
        self.pos += bytes.len();
        Some(())
    }

    fn u32(&mut self, value: u32) -> Option<()> {
        self.bytes(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Option<()> {
        self.bytes(&value.to_le_bytes())
    }

    fn mov_rax(&mut self, value: u64) -> Option<()> {
        self.bytes(&[0x48, 0xb8])?;
        self.u64(value)
    }

    fn mov_rdi(&mut self, value: u64) -> Option<()> {
        self.bytes(&[0x48, 0xbf])?;
        self.u64(value)
    }

    fn mov_rsi(&mut self, value: u64) -> Option<()> {
        self.bytes(&[0x48, 0xbe])?;
        self.u64(value)
    }

    fn mov_rdx(&mut self, value: u64) -> Option<()> {
        self.bytes(&[0x48, 0xba])?;
        self.u64(value)
    }

    fn int80(&mut self) -> Option<()> {
        self.bytes(&[0xcd, 0x80])
    }

    fn syscall3(&mut self, nr: u64, a: u64, b: u64, c: u64) -> Option<()> {
        self.mov_rax(nr)?;
        self.mov_rdi(a)?;
        self.mov_rsi(b)?;
        self.mov_rdx(c)?;
        self.int80()
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn oryvael_syscall_dispatch(frame_ptr: *mut UserTrapFrame) -> u64 {
    if frame_ptr.is_null() {
        return 1;
    }
    // SAFETY: the assembly syscall gate passes its live saved-register frame.
    let frame = unsafe { &mut *frame_ptr };
    match frame.rax {
        SYS_EXIT => {
            unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(USER_EXIT_CODE), frame.rdi) };
            1
        }
        SYS_WRITE => {
            frame.rax = sys_write(frame.rdi, frame.rsi);
            0
        }
        SYS_TICKS => {
            frame.rax = arch::timer_ticks();
            0
        }
        SYS_CAP_SEND => {
            frame.rax = sys_cap_send(frame.rdi, frame.rsi);
            0
        }
        SYS_CAP_RECV => {
            frame.rax = sys_cap_recv(frame.rdi);
            0
        }
        SYS_FS_READ => {
            frame.rax = sys_fs_read(frame.rdi, frame.rsi, frame.rdx);
            0
        }
        _ => {
            frame.rax = u64::MAX;
            0
        }
    }
}

fn sys_write(ptr: u64, len: u64) -> u64 {
    let Some(length) = checked_user_data_range(ptr, len) else {
        return u64::MAX;
    };
    // SAFETY: checked_user_data_range confines reads to the mapped user data page.
    let bytes = unsafe { core::slice::from_raw_parts(ptr as *const u8, length) };
    io::serial_write_bytes(bytes);
    length as u64
}

fn sys_cap_send(handle: u64, value: u64) -> u64 {
    if handle != IPC_CAP {
        return u64::MAX;
    }
    // SAFETY: syscall gate is serialized on the single bootstrap CPU.
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(IPC_MAILBOX_VALUE), value);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(IPC_MAILBOX_FULL), 1);
    }
    0
}

fn sys_cap_recv(handle: u64) -> u64 {
    if handle != IPC_CAP {
        return u64::MAX;
    }
    let full = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(IPC_MAILBOX_FULL)) };
    if full == 0 {
        return u64::MAX - 1;
    }
    let value = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(IPC_MAILBOX_VALUE)) };
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(IPC_MAILBOX_FULL), 0) };
    io::serial_write("ORYVAEL: capability IPC roundtrip value=");
    io::serial_write_u64(value);
    io::serial_write("\r\n");
    value
}

fn sys_fs_read(handle: u64, destination: u64, capacity: u64) -> u64 {
    if handle != RAMFS_CAP {
        return u64::MAX;
    }
    let count = core::cmp::min(capacity as usize, RAMFS_HELLO.len());
    let Some(_) = checked_user_data_range(destination, count as u64) else {
        return u64::MAX;
    };
    // SAFETY: destination range is confined to the writable user data page.
    unsafe {
        core::ptr::copy_nonoverlapping(RAMFS_HELLO.as_ptr(), destination as *mut u8, count)
    };
    io::serial_write("ORYVAEL: ramfs read /hello bytes=");
    io::serial_write_u64(count as u64);
    io::serial_write("\r\n");
    count as u64
}

fn checked_user_data_range(ptr: u64, len: u64) -> Option<usize> {
    let end = ptr.checked_add(len)?;
    let page_end = USER_DATA_VA + USER_PAGE_BYTES as u64;
    if ptr < USER_DATA_VA || end > page_end {
        return None;
    }
    usize::try_from(len).ok()
}

pub fn ramfs_hello() -> &'static [u8] {
    RAMFS_HELLO
}

pub fn mailbox_state() -> (bool, u64) {
    let full = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(IPC_MAILBOX_FULL)) != 0 };
    let value = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(IPC_MAILBOX_VALUE)) };
    (full, value)
}

pub fn exit_code() -> u64 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(USER_EXIT_CODE)) }
}
