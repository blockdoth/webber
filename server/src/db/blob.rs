use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::time::Instant;
use std::{fs, vec};

use crate::runtime::db::db::Connection;
use crate::runtime::misc::byte_stuff::{self};

const BLOB_MAGIC: &[u8; 11] = b"SQLITEBLOB\0";
const BLOB_FOOTER_SIZE: usize = 8 + BLOB_MAGIC.len();

pub struct Blob {}

impl Blob {
    pub fn read_blob(bytes: &[u8]) -> Result<Option<&[u8]>, Box<dyn Error>> {
        if bytes.len() < BLOB_FOOTER_SIZE {
            return Ok(None);
        }

        let magic_offset = bytes.len() - BLOB_MAGIC.len();

        if &bytes[magic_offset..] != BLOB_MAGIC {
            return Ok(None);
        }

        let length_offset = magic_offset - 8;

        let blob_len = usize::from_le_bytes(bytes[length_offset..magic_offset].try_into()?);

        let blob_offset = length_offset - blob_len;

        Ok(Some(&bytes[blob_offset..length_offset]))
    }

    pub fn write_blob<W: Write>(writer: &mut W, blob: &[u8]) -> Result<(), Box<dyn Error>> {
        writer.write_all(blob)?;
        writer.write_all(&(blob.len() as u64).to_le_bytes())?;
        writer.write_all(BLOB_MAGIC)?;

        Ok(())
    }

    fn find_blob_start_offset(file: &mut File) -> Result<u64, Box<dyn Error>> {
        let old_exe_len = file.metadata()?.len() as usize;

        file.seek(SeekFrom::End(-(BLOB_MAGIC.len() as i64)))?;

        let mut magic = vec![0; BLOB_MAGIC.len()];
        file.read_exact(&mut magic)?;

        if magic != BLOB_MAGIC {
            file.seek(SeekFrom::Start(0))?;
            return Ok(old_exe_len as u64);
        }

        let len_offset = BLOB_MAGIC.len() + size_of::<u64>();
        file.seek(SeekFrom::End(-(len_offset as i64)))?;

        let mut len_bytes = [0u8; size_of::<u64>()];
        file.read_exact(&mut len_bytes)?;
        let db_len = usize::from_le_bytes(len_bytes);

        file.seek(SeekFrom::Start(0))?;

        let trailer_len = len_offset + db_len;
        Ok((old_exe_len - trailer_len) as u64)
    }

    pub fn self_modify(path: &PathBuf, conn: &Connection) -> Result<(), Box<dyn Error>> {
        let start_time = Instant::now();

        let serialized = conn.serialize();

        let mut old_exe = File::open("/proc/self/exe")?;

        let perms = old_exe.metadata()?.permissions();

        let tmp = path.with_extension("tmp");

        let blob_start = Self::find_blob_start_offset(&mut old_exe)?;

        let mut tmp_file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)?;

        let old_size = io::copy(&mut old_exe.take(blob_start), &mut tmp_file)?;

        Blob::write_blob(&mut tmp_file, &serialized)?;

        fs::set_permissions(&tmp, perms)?;

        // renames the executable, doesnt affect the currently running process
        fs::rename(&tmp, path)?;

        let end_time = start_time.elapsed();
        println!(
            "Serialized db into {} bytes in {:?}, total blob size {}",
            byte_stuff::pretty_bytes(serialized.len()),
            end_time,
            byte_stuff::pretty_bytes(old_size as usize + serialized.len()),
        );

        Ok(())
    }
}
