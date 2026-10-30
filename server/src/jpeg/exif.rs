use std::fmt::Debug;

use crate::runtime::jpeg::utils::Endian;
use crate::runtime::misc::date::Date;

const TAG_MAKE: u16 = 0x010f;
const TAG_MODEL: u16 = 0x0110;
const TAG_ORIENTATION: u16 = 0x0112;
const TAG_EXIF_IFD: u16 = 0x8769;

const TAG_EXPOSURE_TIME: u16 = 0x829a;
const TAG_F_NUMBER: u16 = 0x829d;
const TAG_ISO: u16 = 0x8827;
const TAG_DATETIME_ORIGINAL: u16 = 0x9003;
const TAG_FOCAL_LENGTH: u16 = 0x920a;
const TAG_LENS_MODEL: u16 = 0xa434;

#[derive(Debug, Default)]
pub struct ExifMetadata {
    pub orientation: Option<u16>,
    pub model: Option<String>,
    pub lens_model: Option<String>,
    pub datetime_original: Option<Date>,

    pub iso: Option<u32>,
    pub exposure_time: Option<f64>,
    pub f_number: Option<f64>,
    pub focal_length: Option<f64>,
}

impl ExifMetadata {
    pub fn parse(tiff: &[u8]) -> Option<ExifMetadata> {
        let tiff = tiff.strip_prefix(b"Exif\0\0")?;

        let endian = match tiff.get(..2)? {
            b"II" => Endian::Little,
            b"MM" => Endian::Big,
            _ => return None,
        };

        if endian.u16(tiff.get(2..)?)? != 42 {
            // hehehe
            return None;
        }

        let ifd0_offset = endian.u32(tiff.get(4..)?)? as usize;

        let mut metadata = ExifMetadata::default();

        let mut exif_ifd_offset = None;

        Self::parse_ifd(
            &tiff[ifd0_offset..],
            endian,
            |tag, ty, count, value| match tag {
                // TAG_MAKE => metadata.make = Self::exif_ascii(tiff, ty, count, value, endian),
                TAG_MODEL => metadata.model = Self::exif_ascii(tiff, ty, count, value, endian),
                TAG_ORIENTATION => {
                    metadata.orientation = Self::exif_u16(tiff, ty, count, value, endian)
                }
                TAG_EXIF_IFD => {
                    exif_ifd_offset =
                        Self::exif_u32(tiff, ty, count, value, endian).map(|v| v as usize)
                }
                _ => {}
            },
        )?;

        if let Some(offset) = exif_ifd_offset {
            Self::parse_ifd(&tiff[offset..], endian, |tag, ty, count, value| match tag {
                TAG_ISO => metadata.iso = Self::exif_unsigned(tiff, ty, count, value, endian),
                TAG_LENS_MODEL => {
                    metadata.lens_model = Self::exif_ascii(tiff, ty, count, value, endian)
                }
                TAG_DATETIME_ORIGINAL
                    if let Some(date) = Self::exif_ascii(tiff, ty, count, value, endian) =>
                {
                    metadata.datetime_original = Date::from_exif_date(date);
                }
                TAG_EXPOSURE_TIME => {
                    metadata.exposure_time = Self::exif_rational(tiff, ty, count, value, endian)
                }
                TAG_F_NUMBER => {
                    metadata.f_number = Self::exif_rational(tiff, ty, count, value, endian)
                }
                TAG_FOCAL_LENGTH => {
                    metadata.focal_length = Self::exif_rational(tiff, ty, count, value, endian)
                }
                _ => {}
            })?;
        }

        Some(metadata)
    }

    fn parse_ifd(
        tiff: &[u8],
        endian: Endian,
        mut handle: impl FnMut(u16, u16, u32, &[u8]),
    ) -> Option<()> {
        let count = endian.u16(tiff)? as usize;

        for i in 0..count {
            let pos = 2 + i * 12;
            let entry = tiff.get(pos..pos + 12)?;

            let tag = endian.u16(&entry[0..2])?;
            let ty = endian.u16(&entry[2..4])?;
            let count = endian.u32(&entry[4..8])?;
            let value = &entry[8..12];

            handle(tag, ty, count, value);
        }

        Some(())
    }

    // Deals with direct value / offset distinction
    fn exif_value_data<'a>(
        tiff: &'a [u8],
        element_size: usize,
        count: u32,
        value: &'a [u8],
        endian: Endian,
    ) -> Option<&'a [u8]> {
        let size = element_size * count as usize;

        if size <= 4 {
            Some(&value[..size])
        } else {
            let offset = endian.u32(value)? as usize;
            Some(&tiff[offset..offset + size])
        }
    }

    fn exif_ascii<'a>(
        tiff: &'a [u8],
        ty: u16,
        count: u32,
        value: &'a [u8],
        endian: Endian,
    ) -> Option<String> {
        // TIFF type 2 = char
        if ty != 2 || count == 0 {
            return None;
        }

        let bytes = Self::exif_value_data(tiff, 1, count, value, endian)?;

        // Zero terminated
        let bytes = bytes.split(|&byte| byte == b'\0').next().unwrap_or(bytes);

        String::from_utf8(bytes.to_vec()).ok()
    }

    fn exif_u16(tiff: &[u8], ty: u16, count: u32, value: &[u8], endian: Endian) -> Option<u16> {
        // TIFF type 3 = u16
        if ty != 3 || count < 1 {
            return None;
        }

        let data = Self::exif_value_data(tiff, 2, count, value, endian)?;

        endian.u16(data)
    }

    fn exif_u32(tiff: &[u8], ty: u16, count: u32, value: &[u8], endian: Endian) -> Option<u32> {
        // TIFF type 4 = u32
        if ty != 4 || count < 1 {
            return None;
        }

        let data = Self::exif_value_data(tiff, 4, count, value, endian)?;

        endian.u32(data)
    }

    fn exif_unsigned(
        tiff: &[u8],
        ty: u16,
        count: u32,
        value: &[u8],
        endian: Endian,
    ) -> Option<u32> {
        match ty {
            // u8
            1 => {
                let data = Self::exif_value_data(tiff, 1, count, value, endian)?;
                Some(*data.first()? as u32)
            }
            // u16
            3 => {
                let data = Self::exif_value_data(tiff, 2, count, value, endian)?;
                Some(endian.u16(data)? as u32)
            }
            // u32
            4 => {
                let data = Self::exif_value_data(tiff, 4, count, value, endian)?;
                endian.u32(data)
            }
            _ => None,
        }
    }

    fn exif_rational(
        tiff: &[u8],
        ty: u16,
        count: u32,
        value: &[u8],
        endian: Endian,
    ) -> Option<f64> {
        // TIFF type 5 = RATIONAL:
        // two u32 values: numerator / denominator.
        if ty != 5 || count < 1 {
            return None;
        }

        let data = Self::exif_value_data(tiff, 8, count, value, endian)?;

        let numerator = endian.u32(&data[0..4])?;
        let denominator = endian.u32(&data[4..8])?;

        if denominator == 0 {
            return None;
        }

        Some(numerator as f64 / denominator as f64)
    }
}
