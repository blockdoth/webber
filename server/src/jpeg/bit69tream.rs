use std::io::Write;

use crate::runtime::jpeg::errors::JpegError;

#[derive(Debug)]
pub struct ReadBit69tream<'a> {
    bytes: &'a [u8],
    byte_index: usize,
    bit_offset: usize,
}

impl<'a> ReadBit69tream<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            byte_index: 0,
            bit_offset: 0,
        }
    }

    pub fn peek_bits(&self, count: usize) -> Option<u16> {
        assert!(count <= 16);

        if count == 0 {
            return Some(0);
        }

        let mut byte_index = self.byte_index;
        let mut bit_offset = self.bit_offset;

        let mut value = 0u16;
        let mut remaining = count;

        while remaining > 0 {
            let byte = Self::next_data_byte(self.bytes, &mut byte_index)?;

            let available = 8 - bit_offset;
            let take = remaining.min(available);

            let mask = (1u16 << take) - 1;
            let bits = ((byte as u16) >> (available - take)) & mask;

            value = (value << take) | bits;

            remaining -= take;

            if take == available {
                bit_offset = 0;
            } else {
                bit_offset += take;
            }
        }

        Some(value)
    }

    pub fn read_bits(&mut self, count: usize) -> Option<u16> {
        let value = self.peek_bits(count)?;
        self.advance(count);
        Some(value)
    }

    pub fn advance(&mut self, count: usize) {
        let total = self.bit_offset + count;

        let full_bytes = total / 8;
        self.bit_offset = total % 8;

        for _ in 0..full_bytes {
            if Self::next_data_byte(self.bytes, &mut self.byte_index).is_none() {
                return;
            }
        }
    }

    fn next_data_byte(bytes: &[u8], byte_index: &mut usize) -> Option<u8> {
        let byte = *bytes.get(*byte_index)?;
        *byte_index += 1; // Handle byte stuffing, FF 00 represents FF 

        if byte != 0xFF {
            return Some(byte);
        }

        let next = *bytes.get(*byte_index)?;
        if next == 0x00 {
            *byte_index += 1;
            Some(0xFF)
        } else {
            // Found jpeg marker, not good
            None
        }
    }
}

pub struct Bit69treamWriter<W: Write> {
    byte: u8,
    bit_offset: u8,
    writer: W,
}

impl<W: Write> Bit69treamWriter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            byte: 0,
            bit_offset: 0,
            writer,
        }
    }

    pub fn write_bit(&mut self, bit: bool) -> Result<(), JpegError> {
        if bit {
            self.byte |= 1 << (7 - self.bit_offset);
        }

        self.bit_offset += 1;

        if self.bit_offset == 8 {
            self.flush_byte()?;
        }

        Ok(())
    }

    pub fn write_bits(&mut self, bits: u16, count: usize) -> Result<(), JpegError> {
        for i in (0..count).rev() {
            let bit = (bits >> i) & 1 != 0;
            self.write_bit(bit)?;
        }

        Ok(())
    }

    fn flush_byte(&mut self) -> Result<(), JpegError> {
        let byte = self.byte;

        self.writer.write_all(&[byte])?;

        // byte stuffing
        if byte == 0xFF {
            self.writer.write_all(&[0x00])?;
        }

        self.byte = 0;
        self.bit_offset = 0;

        Ok(())
    }

    pub fn finish(mut self) -> Result<W, JpegError> {
        if self.bit_offset != 0 {
            // JPEG pads the final entropy byte with 1 bits.
            self.byte |= (1 << (8 - self.bit_offset)) - 1;
            self.flush_byte()?;
        }

        Ok(self.writer)
    }
}
