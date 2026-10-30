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

impl fmt::Display for ImageParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
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

impl From<JpegError> for ImageParseError {
    // Clanker generated, todo, clean up
    fn from(error: JpegError) -> Self {
        match error {
            JpegError::FileToShort | JpegError::UnexpectedEndOfFile => Self::BinaryBlobToShort,
            JpegError::NotAJpeg => Self::InvalidPngSignature,
            JpegError::NotSufficientInfoToDecode
            | JpegError::MetadataNotFound
            | JpegError::ComponentNotFound
            | JpegError::QuantTableNotFound
            | JpegError::HuffmanTableNotFound => Self::DimensionsNotFound,
            JpegError::FailedToParseQuantizationTable
            | JpegError::FailedToParseHuffmanTable
            | JpegError::FailedToParseScan
            | JpegError::FailedToParseScanHeader
            | JpegError::FailedToParseSof0
            | JpegError::FailedToDecodeEntropyData
            | JpegError::UknownColorSpace
            | JpegError::ComponentCountDontMatch
            | JpegError::UnexpectedRepeatedSegment
            | JpegError::ToManyQuantizationTables
            | JpegError::ToManyHuffmanTables => Self::InvalidSegmentLength,
            JpegError::FileNotFound(_)
            | JpegError::UnableToReadFile(_)
            | JpegError::FailedToHuffmanEncode(_)
            | JpegError::WriteError(_) => Self::UnexpectedEof,
        }
    }
}
