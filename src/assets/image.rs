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
    pub fn from_png(path: &str, bin: &[u8]) -> Result<Self, ImageParseError> {
        // println!("{:?}", &bin[..32]);
        use crate::runtime::jpeg::errors::ImageParseError::*;
        if bin.len() < 24 {
            return Err(BinaryBlobToShort);
        }

        if &bin[0..8] != b"\x89PNG\r\n\x1a\n" {
            return Err(InvalidPngSignature);
        }

        if &bin[12..16] != b"IHDR" {
            return Err(MissingIhdrChunk);
        }

        let width = u32::from_be_bytes(bin[16..20].try_into().expect("invariant")) as usize;

        let height = u32::from_be_bytes(bin[20..24].try_into().expect("invariant")) as usize;

        Ok(Self {
            path: path.to_owned(),
            width,
            height,
            metadata: None,
        })
    }

    pub fn from_jpg(path: &str, bytes: &[u8]) -> Result<Self, JpegError> {
        let (metadata, mut width, mut height) = Jpeg::decode_metadata(bytes)?;

        if let Some(metadata) = &metadata
            && matches!(metadata.orientation, Some(5..=8))
        {
            std::mem::swap(&mut width, &mut height)
        }

        Ok(GalleryImage {
            path: path.to_owned(),
            width,
            height,
            metadata,
        })
    }
}
