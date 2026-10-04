use core::arch::asm;

pub const COM1: u16 = 0x3f8;
const PS2_DATA: u16 = 0x60;
const PS2_STATUS_COMMAND: u16 = 0x64;

pub fn serial_init() {
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

pub fn serial_try_read() -> Option<u8> {
    // SAFETY: COM1 status/data ports are fixed x86 I/O ports.
    unsafe {
        if inb(COM1 + 5) & 0x01 != 0 {
            Some(inb(COM1))
        } else {
            None
        }
    }
}

pub fn serial_write(text: &str) {
    serial_write_bytes(text.as_bytes());
}

pub fn serial_write_bytes(bytes: &[u8]) {
    let mut previous = 0u8;
    for &byte in bytes {
        // COM terminals require CRLF. Ring-3 writes are allowed to use plain
        // Unix LF, so normalize them at the single serial output boundary.
        if byte == b'\n' && previous != b'\r' {
            serial_write_byte(b'\r');
        }
        serial_write_byte(byte);
        previous = byte;
    }
}

pub fn serial_write_byte(byte: u8) {
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

pub fn serial_write_u64(mut value: u64) {
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

pub fn serial_write_hex(value: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    serial_write("0x");
    for shift in (0..16).rev() {
        let nibble = ((value >> (shift * 4)) & 0xf) as usize;
        serial_write_byte(HEX[nibble]);
    }
}

pub struct KeyboardState {
    shift: bool,
}

impl KeyboardState {
    pub const fn new() -> Self {
        Self { shift: false }
    }

    pub fn try_read_ascii(&mut self) -> Option<u8> {
        // SAFETY: polling the i8042 is the sole keyboard consumer in this stage.
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
        0x02 => {
            if shift {
                b'!'
            } else {
                b'1'
            }
        }
        0x03 => {
            if shift {
                b'@'
            } else {
                b'2'
            }
        }
        0x04 => {
            if shift {
                b'#'
            } else {
                b'3'
            }
        }
        0x05 => {
            if shift {
                b'$'
            } else {
                b'4'
            }
        }
        0x06 => {
            if shift {
                b'%'
            } else {
                b'5'
            }
        }
        0x07 => {
            if shift {
                b'^'
            } else {
                b'6'
            }
        }
        0x08 => {
            if shift {
                b'&'
            } else {
                b'7'
            }
        }
        0x09 => {
            if shift {
                b'*'
            } else {
                b'8'
            }
        }
        0x0a => {
            if shift {
                b'('
            } else {
                b'9'
            }
        }
        0x0b => {
            if shift {
                b')'
            } else {
                b'0'
            }
        }
        0x0c => {
            if shift {
                b'_'
            } else {
                b'-'
            }
        }
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
        0x34 => {
            if shift {
                b'>'
            } else {
                b'.'
            }
        }
        0x39 => b' ',
        _ => return None,
    };
    Some(byte)
}

fn letter(lower: u8, shift: bool) -> u8 {
    if shift { lower - 32 } else { lower }
}

pub fn disable_interrupts() {
    // SAFETY: caller is in kernel privilege level and controls the IDT path.
    unsafe { asm!("cli", options(nomem, nostack)) };
}

pub fn enable_interrupts() {
    // SAFETY: called only after an interrupt table and timer path exist.
    unsafe { asm!("sti", options(nomem, nostack)) };
}

pub fn cpu_relax() {
    core::hint::spin_loop();
}

pub fn halt_forever() -> ! {
    disable_interrupts();
    loop {
        // SAFETY: terminal kernel stop path.
        unsafe { asm!("hlt", options(nomem, nostack)) };
    }
}

pub fn reboot() -> ! {
    disable_interrupts();
    for _ in 0..100_000 {
        // SAFETY: i8042 status port is fixed on PC-compatible x86 hardware.
        if unsafe { inb(PS2_STATUS_COMMAND) } & 0x02 == 0 {
            break;
        }
        core::hint::spin_loop();
    }
    // SAFETY: command 0xfe asks the controller to pulse CPU reset.
    unsafe { outb(PS2_STATUS_COMMAND, 0xfe) };
    halt_forever()
}

pub unsafe fn io_wait() {
    // SAFETY: port 0x80 is the conventional PC POST delay port.
    unsafe { outb(0x80, 0) };
}

pub unsafe fn outb(port: u16, value: u8) {
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

pub unsafe fn inb(port: u16) -> u8 {
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

pub unsafe fn outw(port: u16, value: u16) {
    // SAFETY: caller selects a valid x86 I/O port.
    unsafe {
        asm!(
            "out dx, ax",
            in("dx") port,
            in("ax") value,
            options(nomem, nostack, preserves_flags)
        )
    };
}

pub unsafe fn outl(port: u16, value: u32) {
    // SAFETY: caller selects a valid x86 I/O port.
    unsafe {
        asm!(
            "out dx, eax",
            in("dx") port,
            in("eax") value,
            options(nomem, nostack, preserves_flags)
        )
    };
}

pub unsafe fn inl(port: u16) -> u32 {
    let value: u32;
    // SAFETY: caller selects a valid x86 I/O port.
    unsafe {
        asm!(
            "in eax, dx",
            in("dx") port,
            out("eax") value,
            options(nomem, nostack, preserves_flags)
        )
    };
    value
}
