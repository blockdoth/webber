use std::error::Error;
use std::fmt::Debug;
use std::fs::File;
use std::io::{BufWriter, ErrorKind, Write};
use std::{fs, vec};

use crate::runtime::jpeg::bit69tream::{Bit69treamWriter, ReadBit69tream};
use crate::runtime::jpeg::errors::JpegError;
use crate::runtime::jpeg::exif::ExifMetadata;
use crate::runtime::jpeg::huffman::{HuffmanClass, HuffmanCodeBook, HuffmanTable, HuffmanTree};
use crate::runtime::jpeg::quant::QuantizationTable;
use crate::runtime::jpeg::utils::{ColorSpace, JpegNum};

pub const TAG_SOI: u16 = 0xFFD8; // Start Of Image
pub const TAG_APP0: u16 = 0xFFE0; // JFIF
pub const TAG_APP1: u16 = 0xFFE1; // EXIF / XMP
pub const TAG_APP2: u16 = 0xFFE2; // ICC profile
pub const TAG_DQT: u16 = 0xFFDB; // Define Quantization Table
pub const TAG_SOF0: u16 = 0xFFC0; // Baseline DCT
pub const TAG_DHT: u16 = 0xFFC4; // Define Huffman Table
pub const TAG_SOS: u16 = 0xFFDA; // Start Of Scan
pub const TAG_EOI: u16 = 0xFFD9; // End Of Image
pub const JPEG_MAGIC: [u8; 5] = [0x4A, 0x46, 0x49, 0x46, 0x00]; // "JFIF"

#[allow(clippy::zero_prefixed_literal)]
pub const ZIGZAG_LOOKUP: [usize; 64] = [
    00, 01, 05, 06, 14, 15, 27, 28, //
    02, 04, 07, 13, 16, 26, 29, 42, //
    03, 08, 12, 17, 25, 30, 41, 43, //
    09, 11, 18, 24, 31, 40, 44, 53, //
    10, 19, 23, 32, 39, 45, 52, 54, //
    20, 22, 33, 38, 46, 51, 55, 60, //
    21, 34, 37, 47, 50, 56, 59, 61, //
    35, 36, 48, 49, 57, 58, 62, 63, //
];

#[allow(clippy::zero_prefixed_literal)]
pub const ZIGZAG_INVERSE: [usize; 64] = [
    00, 01, 08, 16, 09, 02, 03, 10, //
    17, 24, 32, 25, 18, 11, 04, 05, //
    12, 19, 26, 33, 40, 48, 41, 34, //
    27, 20, 13, 06, 07, 14, 21, 28, //
    35, 42, 49, 56, 57, 50, 43, 36, //
    29, 22, 15, 23, 30, 37, 44, 51, //
    58, 59, 52, 45, 38, 31, 39, 46, //
    53, 60, 61, 54, 47, 55, 62, 63, //
];

#[derive(Debug)]
pub struct Jpeg {
    quant_tables: [Option<QuantizationTable>; 4],
    huffman_codebook: HuffmanCodeBook,
    pub metadata: Option<ExifMetadata>,
    sof0: Sof0,
    scan_header: ScanHeader,
    jpeg_decoding_data: JpegDecodeMetadata,
    app_1_blob: Option<Vec<u8>>,
    pub image_data: Vec<u8>,
    pub colorspace: ColorSpace,
}
// Jpeg Structure https://github.com/corkami/formats/blob/master/image/jpeg.md
// Inspired by https://github.com/image-rs/jpeg-decoder
impl Jpeg {
    pub fn decode(path: &str) -> Result<Jpeg, JpegError> {
        use JpegError::*;
        println!("Decoding {path:?}");

        let bytes = fs::read(path).map_err(|err| {
            if err.kind() == ErrorKind::NotFound {
                FileNotFound(path.to_owned())
            } else {
                UnableToReadFile(path.to_owned())
            }
        })?;

        let mut sof0: Option<Sof0> = None;
        let mut metadata: Option<ExifMetadata> = None;
        let mut quant_tables: [Option<QuantizationTable>; 4] = [const { None }; 4];
        let mut huffman_codebook = HuffmanCodeBook {
            ac: [const { None }; 4],
            dc: [const { None }; 4],
        };

        let mut cursor = 0;

        let mut app1_blob_start = 0;
        let mut app1_blob_end = 0;
        while cursor + 1 < bytes.len() {
            let marker = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]);

            match marker {
                TAG_SOI => {
                    println!("SOI - Start of Image");
                    cursor += 2;
                }

                TAG_EOI => {
                    println!("EOI - End of Image");
                    break;
                }

                TAG_SOS => {
                    println!("SOS - Start of Scan");

                    if let Some(sof0) = sof0
                        && quant_tables.iter().any(|table| table.is_some())
                        && huffman_codebook.ac.iter().any(|table| table.is_some())
                        && huffman_codebook.dc.iter().any(|table| table.is_some())
                    {
                        let (scan_header, offset) = ScanHeader::deserialize(&bytes[cursor + 2..])
                            .ok_or(FailedToParseScanHeader)?;

                        let jpeg_decoding_data = JpegDecodeMetadata::from(&sof0, &scan_header)
                            .ok_or(ComponentCountDontMatch)?;

                        let image_data = Self::decode_entropy(
                            &mut ReadBit69tream::new(&bytes[cursor + offset..]),
                            &jpeg_decoding_data,
                            &huffman_codebook,
                            &quant_tables,
                        )
                        .ok_or(FailedToDecodeEntropyData)?;

                        let app_1_blob = if app1_blob_end != 0 {
                            Some(bytes[app1_blob_start..app1_blob_end].to_vec())
                        } else {
                            None
                        };

                        let colorspace = ColorSpace::decode(jpeg_decoding_data.components.len());

                        return Ok(Jpeg {
                            sof0,
                            quant_tables,
                            huffman_codebook,
                            scan_header,
                            metadata,
                            app_1_blob,
                            image_data,
                            colorspace,
                            jpeg_decoding_data,
                        });
                    } else {
                        return Err(NotSufficientInfoToDecode);
                    }
                }

                TAG_SOF0 => {
                    let segment_len = Self::segment_len(&bytes, cursor);
                    println!("SOF0 - Baseline DCT, {segment_len} bytes");

                    cursor += 4;

                    if sof0.is_none() {
                        sof0 = Some(Sof0::deserialize(&bytes[cursor..]).ok_or(FailedToParseSof0)?);
                    } else {
                        return Err(UnexpectedRepeatedSegment);
                    }
                    cursor += segment_len;
                }

                TAG_DHT => {
                    let segment_len = Self::segment_len(&bytes, cursor);
                    println!("DHT - Define Huffman Table, {segment_len} bytes");
                    cursor += 4;

                    if let Some(huff_table) = HuffmanTable::decode(&bytes[cursor..]) {
                        let idx = huff_table.id as usize;

                        match huff_table.class {
                            HuffmanClass::Ac => {
                                huffman_codebook.ac[idx] = Some(HuffmanTree::new(huff_table))
                            }
                            HuffmanClass::Dc => {
                                huffman_codebook.dc[idx] = Some(HuffmanTree::new(huff_table))
                            }
                        }
                    } else {
                        return Err(FailedToParseHuffmanTable);
                    }
                    cursor += segment_len;
                }

                TAG_DQT => {
                    let segment_len = Self::segment_len(&bytes, cursor);
                    println!("DQT - Define Quantization Table, {segment_len} bytes");
                    cursor += 4;

                    if let Some(quant_table) = QuantizationTable::decode(&bytes[cursor..]) {
                        let id = quant_table.id as usize;
                        quant_tables[id] = Some(quant_table.unzig());
                    } else {
                        return Err(FailedToParseQuantizationTable);
                    }
                    cursor += segment_len;
                }
                TAG_APP0 => {
                    let segment_len = Self::segment_len(&bytes, cursor);
                    println!("APP0 - JFIF, {segment_len} bytes");

                    cursor += 4;
                    if bytes.get(cursor..cursor + 5).ok_or(FileToShort)? != JPEG_MAGIC {
                        return Err(NotAJpeg);
                    }
                    cursor += segment_len;
                }

                TAG_APP1 => {
                    let segment_len = Self::segment_len(&bytes, cursor);
                    println!("APP1 - EXIF/XMP, {segment_len} bytes");
                    app1_blob_start = cursor + 4;
                    metadata = ExifMetadata::parse(&bytes[cursor + 4..]);

                    cursor += segment_len + 4;
                    app1_blob_end = cursor;
                }

                TAG_APP2 => {
                    let segment_len = Self::segment_len(&bytes, cursor);
                    println!("APP2 - ICC, {segment_len} bytes");
                    cursor += segment_len + 4;
                }
                _ => {
                    cursor += 1;
                }
            }
        }
        Err(UnexpectedEndOfFile)
    }

    // https://yasoob.me/posts/understanding-and-writing-jpeg-decoder-in-python/
    //  Remember to remove 0x00
    fn decode_entropy(
        stream: &mut ReadBit69tream,
        metadata: &JpegDecodeMetadata,
        huff_book: &HuffmanCodeBook,
        quant_tables: &[Option<QuantizationTable>; 4],
    ) -> Option<Vec<u8>> {
        let max_h_samples = metadata
            .components
            .iter()
            .map(|c| c.horizontal_sampling)
            .max()? as usize;

        let max_v_samples = metadata
            .components
            .iter()
            .map(|c| c.vertical_sampling)
            .max()? as usize;

        let mcu_width = max_h_samples * 8;
        let mcu_height = max_v_samples * 8;

        let mcu_x_count = metadata.width.div_ceil(mcu_width);

        let mcu_y_count = metadata.height.div_ceil(mcu_height);

        let mut prev_dcs = [0i16; 4];

        let mut image = vec![0; metadata.height * metadata.width * metadata.components.len()];

        for mcu_y in 0..mcu_y_count {
            for mcu_x in 0..mcu_x_count {
                let components = McuComponents::decode(
                    stream,
                    metadata,
                    huff_book,
                    quant_tables,
                    &mut prev_dcs,
                )?;

                let planes = components.up_sample(max_h_samples, max_v_samples);

                McuComponents::write_mcu(
                    &mut image,
                    &planes,
                    metadata.width,
                    metadata.height,
                    mcu_x,
                    mcu_y,
                    mcu_width,
                    mcu_height,
                );
            }
        }

        Some(image)
    }

    pub fn decode_metadata(
        bytes: &[u8],
    ) -> Result<(Option<ExifMetadata>, usize, usize), JpegError> {
        use JpegError::*;

        let mut cursor = 0;

        let mut width = None;
        let mut height = None;
        let mut exif_data = None;

        while cursor + 2 < bytes.len() {
            match u16::from_be_bytes(bytes[cursor..cursor + 2].try_into().unwrap()) {
                TAG_EOI | TAG_SOS => {
                    break;
                }

                TAG_SOF0 => {
                    let segment_len = Jpeg::segment_len(bytes, cursor);
                    cursor += 4;

                    let sof0 = Sof0::deserialize(&bytes[cursor..]).ok_or(UnexpectedEndOfFile)?;

                    width = Some(sof0.width);
                    height = Some(sof0.height);
                    cursor += segment_len;
                }
                TAG_APP1 => {
                    let segment_len = Jpeg::segment_len(bytes, cursor);
                    cursor += 4;

                    exif_data = ExifMetadata::parse(&bytes[cursor..]);
                    cursor += segment_len;
                }
                TAG_APP0 | TAG_APP2 | TAG_DHT | TAG_DQT => {
                    let segment_len = Jpeg::segment_len(bytes, cursor);
                    cursor += 4;
                    cursor += segment_len;
                }
                _ => {
                    cursor += 1;
                }
            }
        }

        Ok((
            exif_data,
            width.ok_or(MetadataNotFound)?,
            height.ok_or(MetadataNotFound)?,
        ))
    }

    pub fn encode(self, path: &str) -> Result<(), Box<dyn Error>> {
        let mut writer = File::create(path)?;
        // APP0
        writer.write_all(&TAG_SOI.to_be_bytes())?;
        writer.write_all(&TAG_APP0.to_be_bytes())?;
        writer.write_all(&(JPEG_MAGIC.len() as u16 + 2).to_be_bytes())?;
        writer.write_all(&JPEG_MAGIC)?;

        if let Some(app_1) = &self.app_1_blob {
            let blob_len = app_1.len() as u16 + 2;
            writer.write_all(&TAG_APP1.to_be_bytes())?;
            writer.write_all(&blob_len.to_be_bytes())?;
            writer.write_all(app_1)?;
        }

        for quant in self.quant_tables.iter().flatten() {
            quant.encode(&mut writer)?;
        }

        self.sof0.encode(&mut writer)?;

        for huff in self
            .huffman_codebook
            .ac
            .iter()
            .chain(self.huffman_codebook.dc.iter())
            .flatten()
        {
            huff.table.encode(&mut writer)?;
        }

        let width = self.sof0.width;
        let height = self.sof0.height;

        let blocks_x = width.div_ceil(16);
        let blocks_y = height.div_ceil(16);

        let mut mcus = McuComponents {
            components: Vec::with_capacity(blocks_x * blocks_y * self.sof0.components.len()),
        };

        for mcu_y in 0..blocks_y {
            for mcu_x in 0..blocks_x {
                let mut y_superblock = [[0i16; 16]; 16];
                let mut cb_superblock = [[0i16; 16]; 16];
                let mut cr_superblock = [[0i16; 16]; 16];

                for y in 0..16 {
                    for x in 0..16 {
                        let px = (mcu_x * 16 + x).min(width - 1);
                        let py = (mcu_y * 16 + y).min(height - 1);

                        let rgb_idx = (py * width + px) * 3;

                        let [r, g, b] = self.image_data[rgb_idx..rgb_idx + 3].try_into().unwrap();

                        let [yc, cbv, crv] = ColorSpace::rgb_to_ycbcr(r, g, b);

                        y_superblock[y][x] = yc as i16;
                        cb_superblock[y][x] = cbv as i16;
                        cr_superblock[y][x] = crv as i16;
                    }
                }

                for component in &self.sof0.components {
                    let h = component.horizontal_sampling as usize;
                    let v = component.vertical_sampling as usize;

                    let blocks = match component.id {
                        1 => Self::subdivide_2x2(&y_superblock),         // Y
                        2 => vec![Self::downsample_2x2(&cb_superblock)], // Cb
                        3 => vec![Self::downsample_2x2(&cr_superblock)], // Cr
                        _ => panic!("unsupported component {}", component.id),
                    };
                    // println!("Block");
                    // for row in blocks[0].data.chunks(8) {
                    //   println!("{row:?}");
                    // }

                    mcus.components.push(McuComponent {
                        id: component.id,
                        horizontal_sampling: h,
                        vertical_sampling: v,
                        blocks,
                    });
                }
            }
        }
        let header_len = (2 + 1 + 2 * self.scan_header.components.len() + 3) as u16;

        self.scan_header.encode(&mut writer, header_len)?;
        mcus.encode(
            &mut writer,
            &self.jpeg_decoding_data.components,
            &self.huffman_codebook,
            &self.quant_tables,
        )?;

        writer.write_all(&TAG_EOI.to_be_bytes())?;

        Ok(())
    }

    fn downsample_2x2(input: &[[i16; 16]; 16]) -> Block {
        let mut data = [0i16; 64];

        for y in 0..8 {
            for x in 0..8 {
                let a = input[y * 2][x * 2];
                let b = input[y * 2][x * 2 + 1];
                let c = input[y * 2 + 1][x * 2];
                let d = input[y * 2 + 1][x * 2 + 1];

                data[y * 8 + x] = (a + b + c + d) / 4;
            }
        }

        Block { data }
    }
    fn subdivide_2x2(input: &[[i16; 16]; 16]) -> Vec<Block> {
        let mut blocks = vec![];

        for block_y in 0..2 {
            for block_x in 0..2 {
                let mut data = [0i16; 64];

                for y in 0..8 {
                    for x in 0..8 {
                        let src_y = block_y * 8 + y;
                        let src_x = block_x * 8 + x;

                        data[y * 8 + x] = input[src_y][src_x];
                    }
                }

                blocks.push(Block { data });
            }
        }
        blocks
    }

    fn segment_len(bytes: &[u8], cursor: usize) -> usize {
        u16::from_be_bytes([bytes[cursor + 2], bytes[cursor + 3]]) as usize - 2
    }

    fn write_ppm(&self, path: &str) -> Result<(), Box<dyn Error>> {
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);

        write!(
            writer,
            "P6\n{} {}\n255\n",
            self.sof0.width, self.sof0.height
        )?;

        writer.write_all(&self.image_data)?;

        Ok(())
    }
}

#[derive(Debug)]
struct Block {
    data: [i16; 64],
}

impl Default for Block {
    fn default() -> Self {
        Self { data: [0; 64] }
    }
}

impl Block {
    fn decode(
        stream: &mut ReadBit69tream,
        component: &JpegDecodeMetadataComponent,
        huff_book: &HuffmanCodeBook,
        quant_tables: &[Option<QuantizationTable>; 4],
        prev_dc: &mut i16,
    ) -> Option<Block> {
        let jpeg_num_len = huff_book
            .dc
            .get(component.dc_table)?
            .as_ref()?
            .decode(stream)? as usize;
        let jpeg_num = stream.read_bits(jpeg_num_len)?;

        let dc = *prev_dc + JpegNum::decode(jpeg_num, jpeg_num_len);
        *prev_dc = dc;

        let mut block = Block::default();
        block.data[0] = dc;

        let mut cursor = 1;
        while cursor <= 63 {
            let symbol = huff_book
                .ac
                .get(component.ac_table)?
                .as_ref()?
                .decode(stream)?;

            let run = (symbol >> 4) as usize;
            let jpeg_num_len = (symbol & 0x0F) as usize;

            if jpeg_num_len == 0 {
                // EOB - end of block
                if run == 0 {
                    break;
                } else if run == 15 {
                    // ZRL - empty row
                    cursor += 16;
                    continue;
                }
            }
            cursor += run;

            let jpeg_num = stream.read_bits(jpeg_num_len)?;
            block.data[ZIGZAG_INVERSE[cursor]] = JpegNum::decode(jpeg_num, jpeg_num_len);
            cursor += 1;
        }

        println!("Encoding Block");
        for row in block.data.chunks(8) {
            println!("{row:?}");
        }
        let block = block.idct(&quant_tables[component.quant_table].as_ref()?.values);

        Some(block)
    }

    fn encode<W: Write>(
        &self,
        stream: &mut Bit69treamWriter<W>,
        dc_table: &HuffmanTree,
        ac_table: &HuffmanTree,
        quant_table: &[u16; 64],
        prev_dc: &mut i16,
    ) -> Result<(), JpegError> {
        use JpegError::*;
        let matrix = self.dct();

        let mut quantized = [0i16; 64];

        for i in 0..64 {
            quantized[i] = (matrix[i] as f64 / quant_table[i] as f64).round() as i16;
        }

        let dc_diff = quantized[0] - *prev_dc;
        *prev_dc = quantized[0];

        let (dc_bits, dc_size) = JpegNum::encode(dc_diff);
        let (huffman_bits, huffman_len) =
            dc_table
                .encode(dc_size)
                .ok_or(FailedToHuffmanEncode(format!(
                    "value={dc_diff}, bits={dc_bits:08b}, size={dc_size}"
                )))?;
        // println!("{dc_diff} {huffman_bits:b} {huffman_len}");

        stream.write_bits(huffman_bits, huffman_len as usize)?;
        stream.write_bits(dc_bits, dc_size as usize)?;

        let mut zero_run = 0usize;

        let mut block = [0i16; 64];
        block[0] = dc_diff;
        for i in 1..64 {
            let value = quantized[ZIGZAG_LOOKUP[i]];
            block[i] = value;
            if value == 0 {
                zero_run += 1;
                continue;
            }

            // ZRL: 16 consecutive zeroes.
            while zero_run >= 16 {
                let (huffman_bits, huffman_len) = ac_table
                    .encode(0xF0)
                    .ok_or(FailedToHuffmanEncode(format!("{:08b}", 0xF0)))?;

                stream.write_bits(huffman_bits, huffman_len as usize)?;

                zero_run -= 16;
            }

            let (ac_bits, ac_size) = JpegNum::encode(value);

            let symbol = ((zero_run as u8) << 4) | ac_size;
            let (huffman_bits, huffman_len) =
                ac_table.encode(symbol).ok_or(FailedToHuffmanEncode(format!("value={value}, bits={ac_bits:08b}, size={ac_size}, run={zero_run}, symbol=0x{symbol:02X}"
              )))?;

            stream.write_bits(huffman_bits, huffman_len as usize)?;
            stream.write_bits(ac_bits, ac_size as usize)?;

            zero_run = 0;
        }
        println!("Decoding Block");
        for row in block.chunks(8) {
            println!("{row:?}");
        }
        // todo!();
        // EOB
        if zero_run > 0 {
            let (huffman_bits, huffman_len) = ac_table
                .encode(0x00)
                .ok_or(FailedToHuffmanEncode(format!("{:08b}", 0x00)))?;

            stream.write_bits(huffman_bits, huffman_len as usize)?;
        }

        Ok(())
    }

    fn idct(&self, quant_table: &[u16; 64]) -> Block {
        use std::f64::consts::PI;

        let mut block = [0i16; 64];

        for y in 0..8 {
            for x in 0..8 {
                let mut sum = 0.0;

                for v in 0..8 {
                    for u in 0..8 {
                        let c_u = if u == 0 { 1.0 / 2.0_f64.sqrt() } else { 1.0 };

                        let c_v = if v == 0 { 1.0 / 2.0_f64.sqrt() } else { 1.0 };

                        let idx = v * 8 + u;
                        let coefficient = self.data[idx] as f64 * quant_table[idx] as f64;

                        let cos_x = ((2 * x + 1) as f64 * u as f64 * PI / 16.0).cos();
                        let cos_y = ((2 * y + 1) as f64 * v as f64 * PI / 16.0).cos();

                        sum += c_u * c_v * coefficient * cos_x * cos_y;
                    }
                }

                // shift from -128 / 128 to 0 / 256
                let value = sum / 4.0 + 128.0;

                block[y * 8 + x] = value.round().clamp(0.0, 255.0) as i16;
            }
        }

        Block { data: block }
    }

    fn dct(&self) -> [i16; 64] {
        use std::f64::consts::PI;

        let mut matrix = [0i16; 64];

        for v in 0..8 {
            for u in 0..8 {
                let c_u = if u == 0 { 1.0 / 2.0_f64.sqrt() } else { 1.0 };

                let c_v = if v == 0 { 1.0 / 2.0_f64.sqrt() } else { 1.0 };

                let mut sum = 0.0;

                for y in 0..8 {
                    for x in 0..8 {
                        // shift from 0 / 256 to -128 / 128

                        let value = self.data[y * 8 + x] as f64 - 128.0;

                        let cos_x = ((2 * x + 1) as f64 * u as f64 * PI / 16.0).cos();
                        let cos_y = ((2 * y + 1) as f64 * v as f64 * PI / 16.0).cos();

                        sum += value * cos_x * cos_y;
                    }
                }

                matrix[v * 8 + u] = (sum * c_u * c_v / 4.0).round() as i16;
            }
        }

        matrix
    }
}

struct McuComponent {
    id: usize,
    horizontal_sampling: usize,
    vertical_sampling: usize,
    blocks: Vec<Block>,
}

impl McuComponent {
    fn upsample(&self, max_h: usize, max_v: usize) -> Vec<i16> {
        let src_width = self.horizontal_sampling * 8;
        let src_height = self.vertical_sampling * 8;

        let target_width = max_h * 8;
        let targer_height = max_v * 8;

        let mut src = vec![0i16; src_width * src_height];

        for block_y in 0..self.vertical_sampling {
            for block_x in 0..self.horizontal_sampling {
                let block = &self.blocks[block_y * self.horizontal_sampling + block_x];

                for y in 0..8 {
                    for x in 0..8 {
                        src[(block_y * 8 + y) * src_width + block_x * 8 + x] =
                            block.data[y * 8 + x];
                    }
                }
            }
        }

        if src_width == target_width && src_height == targer_height {
            return src;
        }

        // Nearest neighbor upsampling
        let mut res = vec![0i16; target_width * targer_height];

        for y in 0..targer_height {
            for x in 0..target_width {
                let src_x = x * src_width / target_width;
                let src_y = y * src_height / targer_height;

                res[y * target_width + x] = src[src_y * src_width + src_x];
            }
        }

        res
    }

    fn down_sample(self, max_h: usize, max_v: usize) -> McuComponent {
        let src_h = self.horizontal_sampling;
        let src_v = self.vertical_sampling;
        let target_h = max_h;
        let target_v = max_v;

        if src_h == target_h && src_v == target_v {
            return self; // Todo look into it
        }

        let scale_x = src_h / target_h;
        let scale_y = src_v / target_v;

        let mut blocks = Vec::with_capacity(src_h * src_v);

        for dst_by in 0..src_v {
            for dst_bx in 0..src_h {
                let mut block = Block::default();

                for y in 0..8 {
                    for x in 0..8 {
                        let src_x = dst_bx * scale_x * 8 + x * scale_x;
                        let src_y = dst_by * scale_y * 8 + y * scale_y;

                        let mut sum = 0i32;

                        for dy in 0..scale_y {
                            for dx in 0..scale_x {
                                let px = src_x + dx;
                                let py = src_y + dy;

                                let block_x = px / 8;
                                let block_y = py / 8;

                                let local_x = px % 8;
                                let local_y = py % 8;

                                sum += self.blocks[block_y * target_h + block_x].data
                                    [local_y * 8 + local_x]
                                    as i32;
                            }
                        }

                        let samples = (scale_x * scale_y) as i32;

                        block.data[y * 8 + x] = (sum / samples) as i16;
                    }
                }

                blocks.push(block);
            }
        }

        McuComponent {
            id: self.id,
            horizontal_sampling: src_h,
            vertical_sampling: src_v,
            blocks,
        }
    }
}

#[test]
fn test_read_bits_across_byte_boundary() {
    let bytes = [0b1010_1010, 0b1100_1100];
    let mut reader = ReadBit69tream::new(&bytes);

    assert_eq!(reader.read_bits(7), Some(0b1010_101));
    assert_eq!(reader.read_bits(2), Some(0b01));
}

struct McuComponents {
    components: Vec<McuComponent>,
}

impl McuComponents {
    fn decode(
        stream: &mut ReadBit69tream,
        decoded_metadata: &JpegDecodeMetadata,
        huff_book: &HuffmanCodeBook,
        quant_tables: &[Option<QuantizationTable>; 4],
        prev_dcs: &mut [i16; 4],
    ) -> Option<McuComponents> {
        let mut components = Vec::with_capacity(4);

        for comp in &decoded_metadata.components {
            let mut blocks =
                Vec::with_capacity((comp.vertical_sampling * comp.horizontal_sampling) as usize);
            for _ in 0..comp.vertical_sampling {
                for _ in 0..comp.horizontal_sampling {
                    let block = Block::decode(
                        stream,
                        comp,
                        huff_book,
                        quant_tables,
                        &mut prev_dcs[comp.id],
                    )?;

                    blocks.push(block);
                }
            }

            components.push(McuComponent {
                id: comp.id,
                horizontal_sampling: comp.horizontal_sampling as usize,
                vertical_sampling: comp.vertical_sampling as usize,
                blocks,
            });
        }
        Some(McuComponents { components })
    }

    fn encode<W: Write>(
        self,
        writer: &mut W,
        components: &[JpegDecodeMetadataComponent],
        huff_book: &HuffmanCodeBook,
        quant_tables: &[Option<QuantizationTable>; 4],
    ) -> Result<(), JpegError> {
        let mut stream = Bit69treamWriter::new(writer);

        let mut prev_dc = [0i16; 4];

        for mcu in self.components {
            let component = components
                .iter()
                .find(|c| c.id == mcu.id)
                .ok_or(JpegError::ComponentNotFound)?;

            let down_sampled = mcu.down_sample(
                component.horizontal_sampling as usize,
                component.vertical_sampling as usize,
            );

            let dc_tree = huff_book.dc[component.dc_table]
                .as_ref()
                .ok_or(JpegError::HuffmanTableNotFound)?;
            let ac_tree = huff_book.ac[component.ac_table]
                .as_ref()
                .ok_or(JpegError::HuffmanTableNotFound)?;
            let quant_table = quant_tables[component.quant_table]
                .as_ref()
                .ok_or(JpegError::QuantTableNotFound)?;

            for block in &down_sampled.blocks {
                block.encode(
                    &mut stream,
                    dc_tree,
                    ac_tree,
                    &quant_table.values,
                    &mut prev_dc[component.id],
                )?;
            }
        }

        stream.finish()?;

        Ok(())
    }

    fn up_sample(self, max_h_samples: usize, max_v_samples: usize) -> Vec<Vec<i16>> {
        self.components
            .into_iter()
            .map(|component| component.upsample(max_h_samples, max_v_samples))
            .collect::<Vec<_>>()
    }

    #[allow(clippy::too_many_arguments)]
    fn write_mcu(
        image: &mut [u8],
        planes: &[Vec<i16>],
        image_width: usize,
        image_height: usize,
        mcu_x: usize,
        mcu_y: usize,
        mcu_width: usize,
        mcu_height: usize,
    ) {
        let color_space = ColorSpace::decode(planes.len());

        match color_space {
            ColorSpace::YCbCr => {
                let y_plane = &planes[0];
                let cb_plane = &planes[1];
                let cr_plane = &planes[2];

                for y in 0..mcu_height {
                    for x in 0..mcu_width {
                        let image_x = mcu_x * mcu_width + x;
                        let image_y = mcu_y * mcu_height + y;

                        // Last MCU may extend past the image dimensions.
                        if image_x >= image_width || image_y >= image_height {
                            continue;
                        }

                        let plane_index = y * mcu_width + x;

                        let rgb = ColorSpace::ycbcr_to_rgb(
                            y_plane[plane_index],
                            cb_plane[plane_index],
                            cr_plane[plane_index],
                        );

                        let image_index = (image_y * image_width + image_x) * 3;

                        image[image_index..image_index + 3].copy_from_slice(&rgb);
                    }
                }
            }
            ColorSpace::Grayscale => {
                let y_plane = &planes[0];

                for y in 0..mcu_height {
                    for x in 0..mcu_width {
                        let image_x = mcu_x * mcu_width + x;
                        let image_y = mcu_y * mcu_height + y;

                        // Last MCU may extend past the image dimensions.
                        if image_x >= image_width || image_y >= image_height {
                            continue;
                        }

                        let plane_index = y * mcu_width + x;

                        let image_index = image_y * image_width + image_x;

                        image[image_index] = y_plane[plane_index] as u8;
                    }
                }
            }
            _ => todo!(),
        }
    }
}

#[derive(Debug)]
struct Sof0 {
    precision: u8,
    width: usize,
    height: usize,
    components: Vec<Sof0Component>,
}

impl Sof0 {
    fn deserialize(bytes: &[u8]) -> Option<Sof0> {
        let precision = *bytes.first()?;

        let height = u16::from_be_bytes([*bytes.get(1)?, *bytes.get(2)?]) as usize;
        let width = u16::from_be_bytes([*bytes.get(3)?, *bytes.get(4)?]) as usize;

        let component_count = *bytes.get(5)? as usize;

        let mut components = Vec::with_capacity(component_count);

        for i in 0..component_count {
            let offset = 1 + 2 + 2 + 1 + i * 3;

            let id = *bytes.get(offset)? as usize;
            let sampling_h_and_v = *bytes.get(offset + 1)?;
            let quantization_table = *bytes.get(offset + 2)?;

            components.push(Sof0Component {
                id,
                horizontal_sampling: sampling_h_and_v >> 4,
                vertical_sampling: sampling_h_and_v & 0x0F,
                quantization_table,
            });
        }

        Some(Sof0 {
            precision,
            width,
            height,
            components,
        })
    }

    fn encode<W: Write>(&self, writer: &mut W) -> Result<(), JpegError> {
        writer.write_all(&TAG_SOF0.to_be_bytes())?;
        let size = 8 + 3 * self.components.len() as u16;
        writer.write_all(&size.to_be_bytes())?;
        writer.write_all(&[self.precision])?;
        writer.write_all(&(self.height as u16).to_be_bytes())?;
        writer.write_all(&(self.width as u16).to_be_bytes())?;

        writer.write_all(&[self.components.len() as u8])?;

        for comp in &self.components {
            writer.write_all(&[comp.id as u8])?;

            writer.write_all(&[(comp.horizontal_sampling << 4) | comp.vertical_sampling])?;
            writer.write_all(&[comp.quantization_table])?;
        }

        Ok(())
    }
}

#[derive(Debug)]
struct Sof0Component {
    id: usize,
    horizontal_sampling: u8,
    vertical_sampling: u8,
    quantization_table: u8,
}

#[derive(Debug)]
struct ScanComponent {
    id: usize,
    dc_table: usize,
    ac_table: usize,
}

#[derive(Debug)]
struct ScanHeader {
    components: Vec<ScanComponent>,
    spectral_start: usize,
    spectral_end: usize,
    successive_approximation: usize,
}

impl ScanHeader {
    fn deserialize(bytes: &[u8]) -> Option<(ScanHeader, usize)> {
        let scan_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;

        let component_count = *bytes.get(2)? as usize;
        let mut components = Vec::with_capacity(component_count);

        let mut offset = 3;

        for _ in 0..component_count {
            let table_byte = bytes.get(offset + 1)?;
            let component = ScanComponent {
                id: *bytes.get(offset)? as usize,
                dc_table: (table_byte >> 4) as usize,
                ac_table: (table_byte & 0x0F) as usize,
            };

            components.push(component);
            offset += 2;
        }

        let offset = 3 + component_count * 2;

        let spectral_start = *bytes.get(offset)? as usize;
        let spectral_end = *bytes.get(offset + 1)? as usize;
        let successive_approximation = *bytes.get(offset + 2)? as usize;

        Some((
            ScanHeader {
                components,
                spectral_start,
                spectral_end,
                successive_approximation,
            },
            scan_len + 2,
        ))
    }

    fn encode<W: Write>(self, writer: &mut W, len: u16) -> Result<(), JpegError> {
        writer.write_all(&TAG_SOS.to_be_bytes())?;
        writer.write_all(&len.to_be_bytes())?;
        writer.write_all(&[self.components.len() as u8])?;

        for comp in self.components {
            writer.write_all(&[comp.id as u8])?;
            writer.write_all(&[(comp.dc_table as u8) << 4 | (comp.ac_table as u8)])?;
        }

        writer.write_all(&[self.spectral_start as u8])?;
        writer.write_all(&[self.spectral_end as u8])?;
        writer.write_all(&[self.successive_approximation as u8])?;

        Ok(())
    }
}

#[derive(Debug)]
struct JpegDecodeMetadata {
    width: usize,
    height: usize,
    components: Vec<JpegDecodeMetadataComponent>,
}

#[derive(Debug)]
struct JpegDecodeMetadataComponent {
    id: usize,
    horizontal_sampling: u8,
    vertical_sampling: u8,
    dc_table: usize,
    ac_table: usize,
    quant_table: usize,
}

impl JpegDecodeMetadata {
    fn from(sof0: &Sof0, scan_header: &ScanHeader) -> Option<Self> {
        let components = scan_header
            .components
            .iter()
            .map(|scan_comp| {
                let sof0_comp = sof0
                    .components
                    .iter()
                    .find(|sof0_comp| sof0_comp.id == scan_comp.id)?;

                Some(JpegDecodeMetadataComponent {
                    id: scan_comp.id,
                    horizontal_sampling: sof0_comp.horizontal_sampling,
                    vertical_sampling: sof0_comp.vertical_sampling,
                    dc_table: scan_comp.dc_table,
                    ac_table: scan_comp.ac_table,
                    quant_table: sof0_comp.quantization_table as usize,
                })
            })
            .collect::<Option<Vec<_>>>()?;

        Some(Self {
            width: sof0.width,
            height: sof0.height,
            components,
        })
    }
}
