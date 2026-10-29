use crate::runtime::jpeg::{
    errors::{ImageParseError, JpegError},
    exif::ExifMetadata,
    jpeg::Jpeg,
};

#[derive(Debug)]
pub struct GalleryImage {
    pub path: String,
    pub width: usize,
    pub height: usize,
    pub metadata: Option<ExifMetadata>,
}

impl GalleryImage {
    pub fn from_png_bytes(path: &str, bytes: &[u8]) -> Result<Self, ImageParseError> {
        let (metadata, width, height) = Png::decode_metadata(bytes)?;
        Ok(Self {
            path: path.to_owned(),
            width,
            height,
            metadata: None,
        })
    }

    pub fn from_jpeg_bytes(path: &str, bytes: &[u8]) -> Result<Self, ImageParseError> {
        let (metadata, mut width, mut height) = Jpeg::decode_metadata(bytes)?;
        Ok(GalleryImage {
            path: path.to_owned(),
            width,
            height,
            metadata,
        })
    }
}

pub struct Png {}

impl Png {
    pub fn decode_metadata(
        bytes: &[u8],
    ) -> Result<(Option<ExifMetadata>, usize, usize), ImageParseError> {
        use crate::runtime::jpeg::errors::ImageParseError::*;
        if bytes.len() < 24 {
            return Err(BinaryBlobToShort);
        }

        if &bytes[0..8] != b"\x89PNG\r\n\x1a\n" {
            return Err(InvalidPngSignature);
        }

        if &bytes[12..16] != b"IHDR" {
            return Err(MissingIhdrChunk);
        }

        let width = u32::from_be_bytes(bytes[16..20].try_into().expect("invariant")) as usize;

        let height = u32::from_be_bytes(bytes[20..24].try_into().expect("invariant")) as usize;

        Ok((None, width, height))
    }
}
