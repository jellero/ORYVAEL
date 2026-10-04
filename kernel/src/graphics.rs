use crate::arch;
use crate::boot::BootGraphics;

const BYTES_PER_PIXEL: usize = 4;
const TARGET_FPS: u64 = 25;
const DEMO_TICKS: u64 = arch::TIMER_HZ * 2;

#[derive(Clone, Copy)]
pub struct Color {
    r: u8,
    g: u8,
    b: u8,
}

impl Color {
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }
}

#[derive(Clone, Copy)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

pub struct Graphics {
    info: BootGraphics,
    draw_base: *mut u8,
    use_backbuffer: bool,
}

impl Graphics {
    pub fn new(info: BootGraphics) -> Option<Self> {
        if info.pixel_format > 1
            || info.width == 0
            || info.height == 0
            || info.pixels_per_scan_line < info.width
            || info.framebuffer_base == 0
        {
            return None;
        }

        let required = (info.pixels_per_scan_line as usize)
            .checked_mul(info.height as usize)?
            .checked_mul(BYTES_PER_PIXEL)?;
        if required > info.framebuffer_size {
            return None;
        }

        let use_backbuffer = info.backbuffer_base != 0 && info.backbuffer_size >= required;
        let draw_base = if use_backbuffer {
            info.backbuffer_base as *mut u8
        } else {
            info.framebuffer_base as *mut u8
        };

        Some(Self {
            info,
            draw_base,
            use_backbuffer,
        })
    }

    pub fn width(&self) -> u32 {
        self.info.width
    }

    pub fn height(&self) -> u32 {
        self.info.height
    }

    pub fn uses_backbuffer(&self) -> bool {
        self.use_backbuffer
    }

    pub fn clear(&mut self, color: Color) {
        self.fill_rect(
            Rect {
                x: 0,
                y: 0,
                width: self.info.width,
                height: self.info.height,
            },
            color,
        );
    }

    pub fn put_pixel(&mut self, x: i32, y: i32, color: Color) {
        if x < 0 || y < 0 || x >= self.info.width as i32 || y >= self.info.height as i32 {
            return;
        }
        let index = y as usize * self.info.pixels_per_scan_line as usize + x as usize;
        self.write_pixel(index, self.pack(color));
    }

    pub fn fill_rect(&mut self, rect: Rect, color: Color) {
        if rect.width == 0 || rect.height == 0 {
            return;
        }
        let x0 = rect.x.max(0).min(self.info.width as i32);
        let y0 = rect.y.max(0).min(self.info.height as i32);
        let x1 = rect
            .x
            .saturating_add(rect.width as i32)
            .max(0)
            .min(self.info.width as i32);
        let y1 = rect
            .y
            .saturating_add(rect.height as i32)
            .max(0)
            .min(self.info.height as i32);
        if x0 >= x1 || y0 >= y1 {
            return;
        }

        let packed = self.pack(color);
        for y in y0..y1 {
            let row = y as usize * self.info.pixels_per_scan_line as usize;
            for x in x0..x1 {
                self.write_pixel(row + x as usize, packed);
            }
        }
    }

    pub fn stroke_rect(&mut self, rect: Rect, thickness: u32, color: Color) {
        if rect.width == 0 || rect.height == 0 || thickness == 0 {
            return;
        }
        let t = thickness.min(rect.width).min(rect.height);
        self.fill_rect(
            Rect {
                x: rect.x,
                y: rect.y,
                width: rect.width,
                height: t,
            },
            color,
        );
        self.fill_rect(
            Rect {
                x: rect.x,
                y: rect.y + rect.height.saturating_sub(t) as i32,
                width: rect.width,
                height: t,
            },
            color,
        );
        self.fill_rect(
            Rect {
                x: rect.x,
                y: rect.y,
                width: t,
                height: rect.height,
            },
            color,
        );
        self.fill_rect(
            Rect {
                x: rect.x + rect.width.saturating_sub(t) as i32,
                y: rect.y,
                width: t,
                height: rect.height,
            },
            color,
        );
    }

    pub fn line(&mut self, mut x0: i32, mut y0: i32, x1: i32, y1: i32, color: Color) {
        let dx = (x1 - x0).abs();
        let sx = if x0 < x1 { 1 } else { -1 };
        let dy = -(y1 - y0).abs();
        let sy = if y0 < y1 { 1 } else { -1 };
        let mut err = dx + dy;

        loop {
            self.put_pixel(x0, y0, color);
            if x0 == x1 && y0 == y1 {
                break;
            }
            let e2 = err.saturating_mul(2);
            if e2 >= dy {
                err += dy;
                x0 += sx;
            }
            if e2 <= dx {
                err += dx;
                y0 += sy;
            }
        }
    }

    pub fn fill_circle(&mut self, cx: i32, cy: i32, radius: i32, color: Color) {
        if radius <= 0 {
            return;
        }
        let r2 = radius.saturating_mul(radius);
        for y in -radius..=radius {
            for x in -radius..=radius {
                if x.saturating_mul(x).saturating_add(y.saturating_mul(y)) <= r2 {
                    self.put_pixel(cx + x, cy + y, color);
                }
            }
        }
    }

    pub fn draw_text(&mut self, mut x: i32, y: i32, text: &str, scale: u32, color: Color) {
        let scale = scale.max(1);
        for byte in text.bytes() {
            self.draw_char(x, y, byte, scale, color);
            x = x.saturating_add((6 * scale) as i32);
        }
    }

    pub fn present(&mut self) {
        if !self.use_backbuffer {
            return;
        }
        let pixels = self.info.pixels_per_scan_line as usize * self.info.height as usize;
        let source = self.draw_base.cast::<u32>();
        let destination = self.info.framebuffer_base as *mut u32;
        for index in 0..pixels {
            // SAFETY: both buffers were validated to hold the complete visible
            // scanout. Volatile destination writes preserve MMIO semantics.
            let value = unsafe { core::ptr::read(source.add(index)) };
            unsafe { core::ptr::write_volatile(destination.add(index), value) };
        }
    }

    fn draw_char(&mut self, x: i32, y: i32, byte: u8, scale: u32, color: Color) {
        let glyph = glyph(byte);
        for (row, bits) in glyph.iter().enumerate() {
            for col in 0..5u32 {
                if bits & (1 << (4 - col)) == 0 {
                    continue;
                }
                self.fill_rect(
                    Rect {
                        x: x + (col * scale) as i32,
                        y: y + (row as u32 * scale) as i32,
                        width: scale,
                        height: scale,
                    },
                    color,
                );
            }
        }
    }

    fn pack(&self, color: Color) -> u32 {
        match self.info.pixel_format {
            // PixelRedGreenBlueReserved8BitPerColor: memory bytes R,G,B,X.
            0 => (color.r as u32) | ((color.g as u32) << 8) | ((color.b as u32) << 16),
            // PixelBlueGreenRedReserved8BitPerColor: memory bytes B,G,R,X.
            1 => (color.b as u32) | ((color.g as u32) << 8) | ((color.r as u32) << 16),
            _ => 0,
        }
    }

    fn write_pixel(&mut self, index: usize, packed: u32) {
        let pointer = unsafe { self.draw_base.add(index * BYTES_PER_PIXEL).cast::<u32>() };
        if self.use_backbuffer {
            // SAFETY: draw_base points to the reserved LoaderData backbuffer.
            unsafe { core::ptr::write(pointer, packed) };
        } else {
            // SAFETY: direct mode targets the validated GOP framebuffer.
            unsafe { core::ptr::write_volatile(pointer, packed) };
        }
    }
}

pub fn run_boot_animation(graphics: &mut Graphics) {
    let start = arch::timer_ticks();
    let end = start.saturating_add(DEMO_TICKS);
    let frame_step = (arch::TIMER_HZ / TARGET_FPS).max(1);
    let mut next_frame = start;

    loop {
        let now = arch::timer_ticks();
        if now >= end {
            break;
        }
        if now >= next_frame {
            let elapsed = now.saturating_sub(start);
            render_boot_frame(graphics, elapsed, DEMO_TICKS);
            graphics.present();
            next_frame = now.saturating_add(frame_step);
        }
        core::hint::spin_loop();
    }

    render_boot_frame(graphics, DEMO_TICKS, DEMO_TICKS);
    graphics.present();
}

fn render_boot_frame(graphics: &mut Graphics, elapsed: u64, total: u64) {
    let width = graphics.width() as i32;
    let height = graphics.height() as i32;
    let background = Color::rgb(7, 9, 13);
    let panel = Color::rgb(15, 20, 27);
    let line = Color::rgb(38, 48, 60);
    let accent = Color::rgb(124, 246, 212);
    let accent2 = Color::rgb(134, 168, 255);
    let text = Color::rgb(232, 238, 245);
    let muted = Color::rgb(116, 128, 143);

    graphics.clear(background);

    for x in (0..width.max(0) as usize).step_by(64) {
        graphics.line(x as i32, 0, x as i32, height - 1, Color::rgb(13, 18, 24));
    }
    for y in (0..height.max(0) as usize).step_by(64) {
        graphics.line(0, y as i32, width - 1, y as i32, Color::rgb(13, 18, 24));
    }

    let margin = (width / 12).max(24);
    let panel_width = (width - margin * 2).max(120) as u32;
    let panel_height = (height / 2).clamp(180, 420) as u32;
    let panel_y = ((height - panel_height as i32) / 2).max(16);
    let panel_rect = Rect {
        x: margin,
        y: panel_y,
        width: panel_width,
        height: panel_height,
    };
    graphics.fill_rect(panel_rect, panel);
    graphics.stroke_rect(panel_rect, 2, line);

    let scale = if width >= 1200 { 4 } else if width >= 700 { 3 } else { 2 };
    let title_width = (7 * 6 * scale) as i32;
    let title_x = ((width - title_width) / 2).max(8);
    let title_y = panel_y + 32;
    graphics.draw_text(title_x, title_y, "ORYVAEL", scale, text);

    let center_x = width / 2;
    let center_y = panel_y + panel_height as i32 / 2 + 12;
    let pulse = ((elapsed % 50) as i32 - 25).abs();
    let radius = 18 + (25 - pulse) / 3;
    graphics.fill_circle(center_x, center_y, radius + 12, Color::rgb(18, 35, 38));
    graphics.fill_circle(center_x, center_y, radius, accent);
    graphics.line(center_x - 44, center_y, center_x - radius - 18, center_y, accent2);
    graphics.line(center_x + radius + 18, center_y, center_x + 44, center_y, accent2);

    let bar_margin = 42i32.min(panel_width as i32 / 6).max(18);
    let bar_x = margin + bar_margin;
    let bar_width = (panel_width as i32 - bar_margin * 2).max(40) as u32;
    let bar_y = panel_y + panel_height as i32 - 54;
    graphics.fill_rect(
        Rect {
            x: bar_x,
            y: bar_y,
            width: bar_width,
            height: 8,
        },
        Color::rgb(27, 35, 45),
    );
    let progress = if total == 0 {
        bar_width
    } else {
        ((bar_width as u64).saturating_mul(elapsed.min(total)) / total) as u32
    };
    graphics.fill_rect(
        Rect {
            x: bar_x,
            y: bar_y,
            width: progress,
            height: 8,
        },
        accent,
    );

    let label_scale = if width >= 700 { 2 } else { 1 };
    graphics.draw_text(bar_x, bar_y + 20, "NATIVE GRAPHICS", label_scale, muted);
}

fn glyph(byte: u8) -> [u8; 7] {
    match byte {
        b'A' => [0b01110, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001],
        b'C' => [0b01110, 0b10001, 0b10000, 0b10000, 0b10000, 0b10001, 0b01110],
        b'E' => [0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b11111],
        b'G' => [0b01110, 0b10001, 0b10000, 0b10111, 0b10001, 0b10001, 0b01110],
        b'H' => [0b10001, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001],
        b'I' => [0b11111, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b11111],
        b'L' => [0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b11111],
        b'N' => [0b10001, 0b11001, 0b10101, 0b10011, 0b10001, 0b10001, 0b10001],
        b'O' => [0b01110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110],
        b'P' => [0b11110, 0b10001, 0b10001, 0b11110, 0b10000, 0b10000, 0b10000],
        b'R' => [0b11110, 0b10001, 0b10001, 0b11110, 0b10100, 0b10010, 0b10001],
        b'S' => [0b01111, 0b10000, 0b10000, 0b01110, 0b00001, 0b00001, 0b11110],
        b'T' => [0b11111, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100],
        b'V' => [0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01010, 0b00100],
        b'Y' => [0b10001, 0b10001, 0b01010, 0b00100, 0b00100, 0b00100, 0b00100],
        b' ' => [0, 0, 0, 0, 0, 0, 0],
        _ => [0b11111, 0b10001, 0b00110, 0b00100, 0b00110, 0b10001, 0b11111],
    }
}
