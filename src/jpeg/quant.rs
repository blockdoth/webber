use std::io::Write;

use crate::runtime::jpeg::{
    errors::JpegError,
    jpeg::{TAG_DQT, ZIGZAG_INVERSE, ZIGZAG_LOOKUP},
};

#[derive(Debug)]
pub struct QuantizationTable {
    pub id: u8,
    pub precision: u8,
    pub values: [u16; 64],
}

impl QuantizationTable {
    pub fn decode(bytes: &[u8]) -> Option<QuantizationTable> {
        let precision_and_id = bytes.first()?;

        let precision = precision_and_id >> 4;
        let id = precision_and_id & 0x0F;

        let width = match precision {
            0 => 1,
            1 => 2,
            _ => return None,
        };
        let mut values = [0u16; 64];

        for (value, chunk) in values.iter_mut().zip(bytes.get(1..)?.chunks_exact(width)) {
            *value = match chunk {
                [x] => *x as u16,
                [hi, lo] => u16::from_be_bytes([*hi, *lo]),
                _ => unreachable!(),
            };
        }
        Some(QuantizationTable {
            id,
            precision,
            values,
        })
    }

    pub fn encode<W: Write>(&self, writer: &mut W) -> Result<(), JpegError> {
        writer.write_all(&TAG_DQT.to_be_bytes())?;
        let length = (2 + 1 + 64 * if self.precision == 0 { 1 } else { 2 }) as u16;
        writer.write_all(&(length).to_be_bytes())?;
        writer.write_all(&[self.precision << 4 | self.id])?;

        let zagged_values = self.zag();

        if self.precision == 0 {
            for &value in &zagged_values {
                writer.write_all(&[value as u8])?;
            }
        } else {
            for &value in &zagged_values {
                writer.write_all(&value.to_be_bytes())?;
            }
        }
        Ok(())
    }
    pub fn unzig(mut self) -> Self {
        let mut values = [0u16; 64];

        for i in 0..64 {
            values[i] = self.values[ZIGZAG_LOOKUP[i]];
        }
        self.values = values;
        self
    }
    pub fn zag(&self) -> [u16; 64] {
        let mut values = [0u16; 64];

        for i in 0..64 {
            values[i] = self.values[ZIGZAG_INVERSE[i]];
        }

        values
    }
}
