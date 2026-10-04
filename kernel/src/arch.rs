use core::arch::{asm, global_asm};
use core::mem::size_of;

use crate::io;

pub const TIMER_HZ: u64 = 100;

const PIC1_COMMAND: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_COMMAND: u16 = 0xa0;
const PIC2_DATA: u16 = 0xa1;
const PIT_CHANNEL0: u16 = 0x40;
const PIT_COMMAND: u16 = 0x43;
const PIT_BASE_HZ: u64 = 1_193_182;

const KERNEL_CODE_SELECTOR: u16 = 0x08;
const KERNEL_DATA_SELECTOR: u16 = 0x10;
const USER_DATA_SELECTOR: u16 = 0x1b;
const USER_CODE_SELECTOR: u16 = 0x23;
const TSS_SELECTOR: u16 = 0x28;
const KERNEL_STACK_BYTES: usize = 64 * 1024;

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

    fn gate(handler: u64, attributes: u8) -> Self {
        Self {
            offset_low: handler as u16,
            selector: KERNEL_CODE_SELECTOR,
            ist: 0,
            attributes,
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
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

#[repr(align(16))]
struct Gdt([u64; 7]);
static mut GDT: Gdt = Gdt([0; 7]);

#[repr(align(16))]
struct TssStorage([u8; 104]);
static mut TSS: TssStorage = TssStorage([0; 104]);

#[repr(align(16))]
struct KernelStack([u8; KERNEL_STACK_BYTES]);
static mut KERNEL_STACK: KernelStack = KernelStack([0; KERNEL_STACK_BYTES]);

#[unsafe(no_mangle)]
pub static mut ORYVAEL_TICKS: u64 = 0;
#[unsafe(no_mangle)]
pub static mut ORYVAEL_USER_PREEMPTIONS: u64 = 0;
#[unsafe(no_mangle)]
pub static mut ORYVAEL_KERNEL_RETURN_RSP: u64 = 0;

unsafe extern "C" {
    static oryvael_exception_table: u8;
    fn oryvael_timer_interrupt();
    fn oryvael_syscall_interrupt();
    fn oryvael_reload_segments();
    fn oryvael_enter_user_asm(rip: u64, rsp: u64);
}

global_asm!(r#"
.global oryvael_reload_segments
oryvael_reload_segments:
    push 0x08
    lea rax, [rip + 1f]
    push rax
    retfq
1:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    xor eax, eax
    mov fs, ax
    mov gs, ax
    ret

.global oryvael_timer_interrupt
oryvael_timer_interrupt:
    push rax
    push rdx
    inc qword ptr [rip + ORYVAEL_TICKS]
    test byte ptr [rsp + 24], 3
    jz 1f
    inc qword ptr [rip + ORYVAEL_USER_PREEMPTIONS]
1:
    mov dx, 0x20
    mov al, 0x20
    out dx, al
    pop rdx
    pop rax
    iretq

.global oryvael_syscall_interrupt
oryvael_syscall_interrupt:
    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8
    push rsi
    push rdi
    push rbp
    push rdx
    push rcx
    push rbx
    push rax
    mov rdi, rsp
    call oryvael_syscall_dispatch
    test rax, rax
    jnz .Lsys_exit
    pop rax
    pop rbx
    pop rcx
    pop rdx
    pop rbp
    pop rdi
    pop rsi
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15
    iretq
.Lsys_exit:
    cli
    mov rsp, qword ptr [rip + ORYVAEL_KERNEL_RETURN_RSP]
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    cld
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

.global oryvael_enter_user_asm
oryvael_enter_user_asm:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov qword ptr [rip + ORYVAEL_KERNEL_RETURN_RSP], rsp
    mov ax, 0x1b
    mov ds, ax
    mov es, ax
    push 0x1b
    push rsi
    pushfq
    pop rax
    or rax, 0x200
    push rax
    push 0x23
    push rdi
    iretq

.global oryvael_exception_table
.align 8
oryvael_exception_table:
    .quad oryvael_exc_0, oryvael_exc_1, oryvael_exc_2, oryvael_exc_3
    .quad oryvael_exc_4, oryvael_exc_5, oryvael_exc_6, oryvael_exc_7
    .quad oryvael_exc_8, oryvael_exc_9, oryvael_exc_10, oryvael_exc_11
    .quad oryvael_exc_12, oryvael_exc_13, oryvael_exc_14, oryvael_exc_15
    .quad oryvael_exc_16, oryvael_exc_17, oryvael_exc_18, oryvael_exc_19
    .quad oryvael_exc_20, oryvael_exc_21, oryvael_exc_22, oryvael_exc_23
    .quad oryvael_exc_24, oryvael_exc_25, oryvael_exc_26, oryvael_exc_27
    .quad oryvael_exc_28, oryvael_exc_29, oryvael_exc_30, oryvael_exc_31

oryvael_exc_0:  push 0; push 0;  jmp oryvael_exc_common
oryvael_exc_1:  push 0; push 1;  jmp oryvael_exc_common
oryvael_exc_2:  push 0; push 2;  jmp oryvael_exc_common
oryvael_exc_3:  push 0; push 3;  jmp oryvael_exc_common
oryvael_exc_4:  push 0; push 4;  jmp oryvael_exc_common
oryvael_exc_5:  push 0; push 5;  jmp oryvael_exc_common
oryvael_exc_6:  push 0; push 6;  jmp oryvael_exc_common
oryvael_exc_7:  push 0; push 7;  jmp oryvael_exc_common
oryvael_exc_8:          push 8;  jmp oryvael_exc_common
oryvael_exc_9:  push 0; push 9;  jmp oryvael_exc_common
oryvael_exc_10:         push 10; jmp oryvael_exc_common
oryvael_exc_11:         push 11; jmp oryvael_exc_common
oryvael_exc_12:         push 12; jmp oryvael_exc_common
oryvael_exc_13:         push 13; jmp oryvael_exc_common
oryvael_exc_14:         push 14; jmp oryvael_exc_common
oryvael_exc_15: push 0; push 15; jmp oryvael_exc_common
oryvael_exc_16: push 0; push 16; jmp oryvael_exc_common
oryvael_exc_17:         push 17; jmp oryvael_exc_common
oryvael_exc_18: push 0; push 18; jmp oryvael_exc_common
oryvael_exc_19: push 0; push 19; jmp oryvael_exc_common
oryvael_exc_20: push 0; push 20; jmp oryvael_exc_common
oryvael_exc_21:         push 21; jmp oryvael_exc_common
oryvael_exc_22: push 0; push 22; jmp oryvael_exc_common
oryvael_exc_23: push 0; push 23; jmp oryvael_exc_common
oryvael_exc_24: push 0; push 24; jmp oryvael_exc_common
oryvael_exc_25: push 0; push 25; jmp oryvael_exc_common
oryvael_exc_26: push 0; push 26; jmp oryvael_exc_common
oryvael_exc_27: push 0; push 27; jmp oryvael_exc_common
oryvael_exc_28: push 0; push 28; jmp oryvael_exc_common
oryvael_exc_29:         push 29; jmp oryvael_exc_common
oryvael_exc_30:         push 30; jmp oryvael_exc_common
oryvael_exc_31: push 0; push 31; jmp oryvael_exc_common

oryvael_exc_common:
    mov rdi, qword ptr [rsp]
    mov rsi, qword ptr [rsp + 8]
    mov rdx, cr2
    and rsp, -16
    call oryvael_exception_dispatch
.Lexception_halt:
    cli
    hlt
    jmp .Lexception_halt
"#);

pub fn initialize() -> bool {
    io::disable_interrupts();
    install_gdt_tss();
    install_idt();
    remap_and_mask_pic();
    program_pit(TIMER_HZ);
    io::enable_interrupts();
    wait_for_timer_tick()
}

fn install_gdt_tss() {
    // SAFETY: initialization runs once on the boot CPU with interrupts disabled.
    unsafe {
        let stack_base = core::ptr::addr_of_mut!(KERNEL_STACK.0).cast::<u8>() as u64;
        let rsp0 = stack_base + KERNEL_STACK_BYTES as u64;
        let tss_base = core::ptr::addr_of_mut!(TSS.0).cast::<u8>();
        core::ptr::write_unaligned(tss_base.add(4).cast::<u64>(), rsp0);
        core::ptr::write_unaligned(tss_base.add(102).cast::<u16>(), 104u16);

        let base = tss_base as u64;
        let limit = 103u64;
        let tss_low = (limit & 0xffff)
            | ((base & 0x00ff_ffff) << 16)
            | (0x89u64 << 40)
            | (((limit >> 16) & 0xf) << 48)
            | (((base >> 24) & 0xff) << 56);
        let tss_high = base >> 32;

        let gdt_ptr = core::ptr::addr_of_mut!(GDT.0).cast::<u64>();
        core::ptr::write(gdt_ptr.add(0), 0);
        core::ptr::write(gdt_ptr.add(1), 0x00af_9a00_0000_ffff);
        core::ptr::write(gdt_ptr.add(2), 0x00cf_9200_0000_ffff);
        core::ptr::write(gdt_ptr.add(3), 0x00cf_f200_0000_ffff);
        core::ptr::write(gdt_ptr.add(4), 0x00af_fa00_0000_ffff);
        core::ptr::write(gdt_ptr.add(5), tss_low);
        core::ptr::write(gdt_ptr.add(6), tss_high);

        let gdtr = DescriptorTablePointer {
            limit: (size_of::<[u64; 7]>() - 1) as u16,
            base: gdt_ptr as u64,
        };
        asm!("lgdt [{}]", in(reg) &gdtr, options(readonly, nostack, preserves_flags));
        oryvael_reload_segments();
        asm!("ltr {0:x}", in(reg) TSS_SELECTOR, options(nostack, preserves_flags));
    }
}

fn install_idt() {
    // SAFETY: exclusive boot-time construction with interrupts disabled.
    unsafe {
        let idt = core::ptr::addr_of_mut!(IDT.0).cast::<IdtEntry>();
        let exception_table = core::ptr::addr_of!(oryvael_exception_table).cast::<usize>();
        for vector in 0..32usize {
            let handler = core::ptr::read(exception_table.add(vector)) as u64;
            core::ptr::write(idt.add(vector), IdtEntry::gate(handler, 0x8e));
        }
        core::ptr::write(
            idt.add(32),
            IdtEntry::gate(oryvael_timer_interrupt as *const () as u64, 0x8e),
        );
        // DPL=3 interrupt gate: user-mode must cross this explicit syscall gate.
        core::ptr::write(
            idt.add(0x80),
            IdtEntry::gate(oryvael_syscall_interrupt as *const () as u64, 0xee),
        );
        let idtr = DescriptorTablePointer {
            limit: (size_of::<[IdtEntry; 256]>() - 1) as u16,
            base: idt as u64,
        };
        asm!("lidt [{}]", in(reg) &idtr, options(readonly, nostack, preserves_flags));
    }
}

fn remap_and_mask_pic() {
    // SAFETY: fixed 8259 ports on the current x86 PC bootstrap target.
    unsafe {
        io::outb(PIC1_COMMAND, 0x11);
        io::io_wait();
        io::outb(PIC2_COMMAND, 0x11);
        io::io_wait();
        io::outb(PIC1_DATA, 0x20);
        io::io_wait();
        io::outb(PIC2_DATA, 0x28);
        io::io_wait();
        io::outb(PIC1_DATA, 0x04);
        io::io_wait();
        io::outb(PIC2_DATA, 0x02);
        io::io_wait();
        io::outb(PIC1_DATA, 0x01);
        io::io_wait();
        io::outb(PIC2_DATA, 0x01);
        io::io_wait();
        io::outb(PIC1_DATA, 0xfe);
        io::outb(PIC2_DATA, 0xff);
    }
}

fn program_pit(hz: u64) {
    let divisor = (PIT_BASE_HZ / hz.max(1)).clamp(1, u16::MAX as u64) as u16;
    // SAFETY: PIT channel 0 is the bootstrap timer for this PC target.
    unsafe {
        io::outb(PIT_COMMAND, 0x36);
        io::outb(PIT_CHANNEL0, divisor as u8);
        io::outb(PIT_CHANNEL0, (divisor >> 8) as u8);
    }
}

fn wait_for_timer_tick() -> bool {
    let before = timer_ticks();
    for _ in 0..50_000_000 {
        if timer_ticks() != before {
            return true;
        }
        io::cpu_relax();
    }
    false
}

pub fn timer_ticks() -> u64 {
    // SAFETY: the timer ISR is the sole writer and aligned u64 loads are atomic.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ORYVAEL_TICKS)) }
}

pub fn user_preemptions() -> u64 {
    // SAFETY: the timer ISR is the sole writer.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ORYVAEL_USER_PREEMPTIONS)) }
}

pub unsafe fn enter_user(rip: u64, rsp: u64) {
    // SAFETY: caller mapped the ring-3 code/stack and initialized GDT/TSS/IDT.
    unsafe { oryvael_enter_user_asm(rip, rsp) };
}

#[unsafe(no_mangle)]
pub extern "C" fn oryvael_exception_dispatch(vector: u64, error: u64, cr2: u64) -> ! {
    io::disable_interrupts();
    io::serial_write("\r\nORYVAEL: exception vector=");
    io::serial_write_u64(vector);
    io::serial_write(" error=");
    io::serial_write_hex(error);
    if vector == 14 {
        io::serial_write(" cr2=");
        io::serial_write_hex(cr2);
    }
    io::serial_write("\r\nORYVAEL: kernel stopped fail-closed\r\n");
    io::halt_forever()
}

pub const fn user_code_selector() -> u16 {
    USER_CODE_SELECTOR
}

pub const fn user_data_selector() -> u16 {
    USER_DATA_SELECTOR
}

pub const fn kernel_data_selector() -> u16 {
    KERNEL_DATA_SELECTOR
}
