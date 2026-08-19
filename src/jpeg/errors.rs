use std::error::Error;
use std::{fmt, io};

impl Error for JpegError {}

#[derive(Debug)]
pub enum JpegError {
    FileNotFound(String),
    UnableToReadFile(String),
    NotSufficientInfoToDecode,
    FileToShort,
    NotAJpeg,
    UnexpectedRepeatedSegment,
    FailedToParseQuantizationTable,
    FailedToParseHuffmanTable,
    FailedToParseScan,
    FailedToParseScanHeader,
    FailedToParseSof0,
    ToManyQuantizationTables,
    ToManyHuffmanTables,
    UknownColorSpace,
    FailedToDecodeEntropyData,
    UnexpectedEndOfFile,
    ComponentCountDontMatch,
    MetadataNotFound,
    QuantTableNotFound,
    HuffmanTableNotFound,
    ComponentNotFound,
    FailedToHuffmanEncode(String),
    WriteError(io::Error),
}

#[derive(Debug)]
pub enum ImageParseError {
    BinaryBlobToShort,
    InvalidPngSignature,
    MissingIhdrChunk,
    UnexpectedEof,
    InvalidSegmentLength,
    DimensionsNotFound,
    InvalidExif,
}

impl fmt::Display for JpegError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<io::Error> for JpegError {
    fn from(error: io::Error) -> Self {
        JpegError::WriteError(error)
    }
}
