use std::io::{self, Read};

pub struct JpegNum {}

impl JpegNum {
    pub fn decode(num: u16, jpeg_num_len: usize) -> i16 {
        if jpeg_num_len == 0 {
            return 0;
        }

        let sign_bit = 1u16 << (jpeg_num_len - 1);

        // Sign bit is set, positive
        if num & sign_bit != 0 {
            return num as i16;
        }

        // Negative
        num as i16 + 1 - (1 << jpeg_num_len)
    }

    pub fn encode(num: i16) -> (u16, u8) {
        if num == 0 {
            return (0, 0);
        }

        let magnitude = num.unsigned_abs();
        let size = 16 - magnitude.leading_zeros() as u8;

        let bits = if num >= 0 {
            magnitude
        } else {
            // JPEG's representation for negative values.
            magnitude ^ ((1u16 << size) - 1)
        };

        (bits, size)
    }
}

#[derive(Debug, PartialEq)]
pub enum ColorSpace {
    Grayscale,
    YCbCr,
    Cmyk,
    Unknown,
}

impl ColorSpace {
    pub fn decode(components: usize) -> ColorSpace {
        match components {
            1 => ColorSpace::Grayscale,
            3 => ColorSpace::YCbCr,
            4 => ColorSpace::Cmyk,
            _ => ColorSpace::Unknown,
        }
    }
    // https://stackoverflow.com/questions/4041840/function-to-convert-ycbcr-to-rgb
    pub fn ycbcr_to_rgb(y: i16, cb: i16, cr: i16) -> [u8; 3] {
        let y = y as f32;
        let cb = cb as f32 - 128.0;
        let cr = cr as f32 - 128.0;

        let r = y + 1.40200 * cr;
        let g = y - 0.34414 * cb - 0.71414 * cr;
        let b = y + 1.77200 * cb;

        [
            r.clamp(0.0, 255.0) as u8,
            g.clamp(0.0, 255.0) as u8,
            b.clamp(0.0, 255.0) as u8,
        ]
    }

    pub fn rgb_to_ycbcr(r: u8, g: u8, b: u8) -> [u8; 3] {
        let r = r as f32;
        let g = g as f32;
        let b = b as f32;

        let y = 0.29900 * r + 0.58700 * g + 0.11400 * b;
        let cb = -0.16874 * r - 0.33126 * g + 0.50000 * b + 128.0;
        let cr = 0.50000 * r - 0.41869 * g - 0.08131 * b + 128.0;

        [
            y.clamp(0.0, 255.0) as u8,
            cb.clamp(0.0, 255.0) as u8,
            cr.clamp(0.0, 255.0) as u8,
        ]
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Endian {
    Little,
    Big,
}

impl Endian {
    pub fn u16(self, bytes: &[u8]) -> Option<u16> {
        let bytes: [u8; 2] = bytes.get(..2)?.try_into().ok()?;

        Some(match self {
            Self::Little => u16::from_le_bytes(bytes),
            Self::Big => u16::from_be_bytes(bytes),
        })
    }

    pub fn u32(self, bytes: &[u8]) -> Option<u32> {
        let bytes: [u8; 4] = bytes.get(..4)?.try_into().ok()?;

        Some(match self {
            Self::Little => u32::from_le_bytes(bytes),
            Self::Big => u32::from_be_bytes(bytes),
        })
    }
}

pub fn read_u8<R: Read>(reader: &mut R) -> io::Result<u8> {
    let mut buf = [0];
    reader.read_exact(&mut buf)?;
    Ok(buf[0])
}

pub fn read_u16_be<R: Read>(reader: &mut R) -> io::Result<u16> {
    let mut buf = [0, 0];
    reader.read_exact(&mut buf)?;
    Ok(u16::from_be_bytes(buf))
}
