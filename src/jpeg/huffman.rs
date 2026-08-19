use std::{collections::HashMap, io::Write};

use crate::runtime::jpeg::{bit69tream::ReadBit69tream, errors::JpegError, jpeg::TAG_DHT};

#[derive(Debug)]
pub struct HuffmanTree {
    pub map: HashMap<(u16, u8), u8>,
    pub encode_map: HashMap<u8, (u16, u8)>,

    pub table: HuffmanTable,
}

impl HuffmanTree {
    pub fn new(table: HuffmanTable) -> HuffmanTree {
        let mut map = HashMap::new();
        let mut encode_map = HashMap::new();

        let mut code = 0u16;
        let mut symbol_index = 0usize;

        for length in 1..=16 {
            let count = table.counts[length - 1];

            for _ in 0..count {
                let symbol = table.symbols[symbol_index];

                map.insert((code, length as u8), symbol);
                encode_map.insert(symbol, (code, length as u8));

                code += 1;
                symbol_index += 1;
            }

            code <<= 1;
        }

        Self {
            map,
            encode_map,
            table,
        }
    }

    pub fn decode(&self, bits: &mut ReadBit69tream) -> Option<u8> {
        for length in 1..=16 {
            let code = bits.peek_bits(length)?;
            if let Some(&symbol) = self.map.get(&(code, length as u8)) {
                bits.advance(length);

                return Some(symbol);
            }
        }

        None
    }

    pub fn encode(&self, symbol: u8) -> Option<(u16, u8)> {
        self.encode_map.get(&symbol).copied()
    }
}

#[derive(Debug)]
pub struct HuffmanCodeBook {
    pub dc: [Option<HuffmanTree>; 4],
    pub ac: [Option<HuffmanTree>; 4],
}
#[derive(Debug)]
pub enum HuffmanClass {
    Ac,
    Dc,
}

#[derive(Debug)]
pub struct HuffmanTable {
    pub class: HuffmanClass,
    pub id: u8,
    pub counts: [u8; 16],

    pub symbols: Vec<u8>,
}

impl HuffmanTable {
    pub fn decode(bytes: &[u8]) -> Option<HuffmanTable> {
        let class_and_id = bytes.first()?;
        let class = match class_and_id >> 4 {
            0 => HuffmanClass::Dc,
            1 => HuffmanClass::Ac,
            _ => return None,
        };

        let id = class_and_id & 0x0F;

        let counts: [u8; 16] = bytes.get(1..17)?.try_into().ok()?;

        let symbol_count: usize = counts.iter().map(|&n| n as usize).sum();

        let symbols = bytes.get(17..17 + symbol_count)?.to_vec();

        Some(HuffmanTable {
            class,
            id,
            counts,
            symbols,
        })
    }

    pub fn encode<W: Write>(&self, writer: &mut W) -> Result<(), JpegError> {
        writer.write_all(&TAG_DHT.to_be_bytes())?;
        let length = 2 + 1 + 16 + self.symbols.len();
        writer.write_all(&(length as u16).to_be_bytes())?;

        let class_and_id = match self.class {
            HuffmanClass::Dc => self.id,
            HuffmanClass::Ac => 0x10 | self.id,
        };

        writer.write_all(&[class_and_id])?;
        writer.write_all(&self.counts)?;
        writer.write_all(&self.symbols)?;

        Ok(())
    }
}
