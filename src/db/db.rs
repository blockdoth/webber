use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::ffi::{CStr, CString, c_int};
use std::fmt::Debug;
use std::iter::zip;
use std::path::PathBuf;
use std::ptr::{null, null_mut};
use std::slice;
use std::str::FromStr;
use std::time::{Duration, SystemTime};
use std::{fs, vec};

#[cfg(generated)]
use crate::comptime::{PREV_BIN_PATH, PREV_BIN_TYPE};
use crate::runtime::db::bindings::{
    SQLITE_DESERIALIZE_FLAG_FREEONCLOSE, SQLITE_DESERIALIZE_FLAG_RESIZEABLE, SQLITE_DONE,
    SQLITE_OK, SQLITE_ROW, sqlite3_bind_blob, sqlite3_bind_int64, sqlite3_bind_text, sqlite3_close,
    sqlite3_column_blob, sqlite3_column_bytes, sqlite3_column_int64, sqlite3_column_text,
    sqlite3_deserialize, sqlite3_errmsg, sqlite3_finalize, sqlite3_handle, sqlite3_malloc64,
    sqlite3_open, sqlite3_prepare_v2, sqlite3_reset, sqlite3_serialize, sqlite3_step, sqlite3_stmt,
};
use crate::runtime::db::blob::Blob;
use crate::runtime::misc::byte_stuff::{self};

pub const METRICS_CACHE_SIZE: usize = 1000;
pub const DB_SYNC_INTERVAL: u64 = 60;

#[derive(Debug)]
pub struct Db {
    connection: Connection,
    executable_path: PathBuf,
    unsynced: bool,
    metric_cache: HashMap<String, Vec<CachedPageHit>>,
    current_cache_count: usize,
}

impl Db {
    pub fn init() -> Result<Self, Box<dyn Error>> {
        let current_executable_path = env::current_exe()?;

        let executable_bytes = fs::read(&current_executable_path)?;

        let conn = match Blob::read_blob(&executable_bytes)? {
            Some(blob) => {
                let conn = Connection::deserialize(blob)?;
                println!(
                    "Blob of length {} found in own binary and serialized into db",
                    byte_stuff::pretty_bytes(blob.len())
                );
                conn
            }
            None => {
                #[cfg(generated)] // PREV_BIN_PATH and PREV_BIN_TYPE dont exist during build time
                if let Some(prev_bin_path) = &PREV_BIN_PATH
                    && let Ok(prev_bin) = fs::read(prev_bin_path)
                    && let Ok(Some(blob)) = Blob::read_blob(&prev_bin)
                    && let Some(prev_bin_type) = &PREV_BIN_TYPE
                {
                    println!(
                        "Blob of length {} found in previous {prev_bin_type} binary and serialized into db",
                        byte_stuff::pretty_bytes(blob.len())
                    );

                    Connection::deserialize(blob)?
                } else {
                    println!("No blob found, creating new db");
                    let conn = Connection::open(":memory:")?;
                    Self::init_schema(&conn)?;
                    conn
                }
                #[cfg(not(generated))]
                unreachable!();
            }
        };
        let mut db = Self {
            connection: conn,
            executable_path: current_executable_path,
            unsynced: true,
            metric_cache: HashMap::new(),
            current_cache_count: 0,
        };
        db.sync()?;
        Ok(db)
    }

    pub fn sync(&mut self) -> Result<(), Box<dyn Error>> {
        if !self.metric_cache.is_empty() {
            self.sync_metric_cache()?;
        }

        if self.unsynced {
            Blob::self_modify(&self.executable_path, &self.connection)?;
            self.unsynced = false;
            Ok(())
        } else {
            Ok(())
        }
    }

    pub fn init_counter(conn: &Connection) -> Result<(), Box<dyn Error>> {
        conn.execute(
            "
            CREATE TABLE counter (
              count INTEGER NOT NULL
            );",
        )?;
        conn.insert(
            "
            INSERT INTO counter (count)
            VALUES (?);",
            &[Bind::Int(0)],
        )?;
        Ok(())
    }
    pub fn init_schema(conn: &Connection) -> Result<(), Box<dyn Error>> {
        Self::init_counter(conn)?;

        conn.execute(
            "
            CREATE TABLE page_metrics (
              id INTEGER PRIMARY KEY,
              page TEXT,
              load_time INTEGER,
              timestamp TIMESTAMP
            );",
        )?;
        conn.execute(
            "
          CREATE TABLE page_metrics_aggregate (
            page TEXT PRIMARY KEY,
            total_load_time INTEGER,
            total_hits INTEGER
          );",
        )?;
        conn.execute(
            "
          CREATE TABLE global_stats (
            id INTEGER PRIMARY KEY,
            start_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
          );",
        )?;
        conn.execute(
            "
        INSERT INTO global_stats (id) VALUES (1)",
        )?;
        Ok(())
    }

    pub fn test_counter(&mut self) -> Result<(), Box<dyn Error>> {
        let conn = &self.connection;

        let res = conn.querry("SELECT count FROM counter", &[], &[ColumnTyp::Int])?;

        let counter_col = res.get_int_column(0).unwrap();
        let counter = *counter_col.first().unwrap();

        println!("Counter: {counter:?}");

        conn.insert(
            "
            UPDATE counter
            SET count = ?;",
            &[Bind::Int(counter + 1)],
        )?;
        self.unsynced = true;
        Ok(())
    }

    pub fn save_page_hit(
        &mut self,
        page_url: &str,
        loadtime: Duration,
    ) -> Result<(), Box<dyn Error>> {
        let timestamp = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
            .cast_signed();

        let loadtime_nanos = i64::from(loadtime.subsec_nanos());

        let hit: CachedPageHit = CachedPageHit {
            loadtime: loadtime_nanos,
            timestamp,
        };

        if let Some(hits) = self.metric_cache.get_mut(page_url) {
            hits.push(hit);
        } else {
            let mut vec = Vec::with_capacity(16);
            vec.push(hit);
            self.metric_cache.insert(page_url.to_owned(), vec);
        }

        self.unsynced = true;
        self.current_cache_count += 1;

        if self.current_cache_count >= METRICS_CACHE_SIZE {
            self.sync_metric_cache()?;
        }

        Ok(())
    }

    // TODO wrap both inserts into transaction
    fn sync_metric_cache(&mut self) -> Result<(), Box<dyn Error>> {
        // let start = Instant::now();
        let conn = &self.connection;

        let aggregates: Vec<(&str, i64, i64)> = self
            .metric_cache
            .iter()
            .map(|(key, hits)| {
                let total_loadtime = hits.iter().map(|hit| hit.loadtime).sum();
                let count = hits.len() as i64;

                (key.as_str(), total_loadtime, count)
            })
            .collect();

        let multi_binds_metrics = self
            .metric_cache
            .iter()
            .flat_map(|(key, hits)| {
                hits.iter().map(|hit| {
                    vec![
                        Bind::Text(key),
                        Bind::Int(hit.loadtime),
                        Bind::Int(hit.timestamp),
                    ]
                })
            })
            .collect();

        let multi_binds_metrics_aggregate = aggregates
            .iter()
            .map(|b| vec![Bind::Text(b.0), Bind::Int(b.1), Bind::Int(b.2)])
            .collect();

        conn.transaction(|| {
            conn.insert_rows_unchecked(
                "INSERT INTO page_metrics (page, load_time, timestamp) VALUES (?,?,?)",
                multi_binds_metrics,
            )?;
            conn.insert_rows_unchecked(
                "
                INSERT INTO page_metrics_aggregate (
                  page,
                  total_load_time,
                  total_hits
                )
                VALUES (?, ?, ?)
                ON CONFLICT(page)
                  DO UPDATE SET
                    total_load_time = total_load_time + excluded.total_load_time,
                    total_hits = total_hits + excluded.total_hits;",
                multi_binds_metrics_aggregate,
            )
        })?;

        self.metric_cache
            .iter_mut()
            .for_each(|(_, hits)| hits.clear());

        self.unsynced = true;
        // let duration = start.elapsed();
        // println!("Synced {} entries in metric cache in {duration:?}",self.current_cache_count );
        self.current_cache_count = 0;

        Ok(())
    }

    pub fn load_stats(&self) -> Result<Stats, Box<dyn Error>> {
        let conn = &self.connection;

        let res = conn.querry(
            "
              SELECT start_time
              FROM global_stats",
            &[],
            &[ColumnTyp::Text],
        )?;
        let col = res.get_text_column(0)?;
        let start_time = col.first().ok_or("Start time not found")?.to_owned();

        let res = conn.querry(
            "
                SELECT page, total_load_time, total_hits
                FROM page_metrics_aggregate",
            &[],
            &[ColumnTyp::Text, ColumnTyp::Int, ColumnTyp::Int],
        )?;

        let pages = res.get_text_column(0)?;
        let total_loadtimes = res.get_int_column(1)?;
        let counts = res.get_int_column(2)?;

        let mut metrics_by_page: HashMap<String, (i64, i64)> = HashMap::with_capacity(pages.len());

        for (page, (total_loadtime, count)) in zip(pages, zip(total_loadtimes, counts)) {
            metrics_by_page.insert(page, (total_loadtime, count));
        }

        for (page, hits) in &self.metric_cache {
            let cached_total = hits.iter().map(|hit| hit.loadtime).sum();
            let cached_count = hits.len() as i64;

            if let Some(entry) = metrics_by_page.get_mut(page) {
                entry.0 += cached_total;
                entry.1 += cached_count;
            } else {
                metrics_by_page.insert(page.to_string(), (cached_total, cached_count));
            }
        }

        let mut metrics: Vec<PageMetric> = metrics_by_page
            .into_iter()
            .map(|(page, (total_loadtime, count))| {
                let average_nanos = total_loadtime / count;

                PageMetric {
                    page,
                    avg_loadtime: Duration::from_nanos(average_nanos as u64),
                    count,
                }
            })
            .collect();

        metrics.sort_unstable_by(|a, b| a.avg_loadtime.cmp(&b.avg_loadtime));
        Ok(Stats {
            pages: metrics,
            start_time,
        })
    }

    pub fn import_db(path: PathBuf) -> Result<(), Box<dyn Error>> {
        let executable_path = env::current_exe()?;

        let connection = Connection::import_db(path)?;
        let mut db = Db {
            connection,
            executable_path,
            unsynced: true,
            metric_cache: HashMap::new(),
            current_cache_count: 0,
        };

        db.sync()?;
        Ok(())
    }

    pub fn export_db_serialized(&mut self, path: PathBuf) -> Result<(), Box<dyn Error>> {
        self.connection.export_db_serialized(path)?;
        self.sync()
    }
    pub fn export_db(&self, path: &PathBuf) -> Result<(), Box<dyn Error>> {
        if path.exists() {
            return Err(format!("Path {path:?} already exists").into());
        }
        let path_str = path.to_string_lossy();
        self.connection
            .insert("VACUUM INTO ?;", &[Bind::Text(&path_str)])
    }
}

#[derive(Debug)]
pub struct Connection {
    handle: *mut sqlite3_handle,
}

impl Connection {
    fn open(path: &str) -> Result<Self, Box<dyn Error>> {
        let c_string = CString::from_str(path)?;
        let mut handle: *mut sqlite3_handle = null_mut();

        let status = unsafe { sqlite3_open(c_string.as_ptr(), &raw mut handle) };

        match status {
            SQLITE_OK => Ok(Self { handle }),
            code => Err(format!("Opening db at {path} failed with code {code}").into()),
        }
    }

    fn transaction<F>(&self, query_fn: F) -> Result<(), Box<dyn Error>>
    where
        F: FnOnce() -> Result<(), Box<dyn Error>>,
    {
        self.execute("BEGIN TRANSACTION;")?;

        match query_fn() {
            Ok(()) => {
                self.execute("COMMIT;")?;
                Ok(())
            }
            Err(error) => {
                let _ = self.execute("ROLLBACK;");
                Err(error)
            }
        }
    }

    fn transaction_multi<F>(&self, query_fns: Vec<F>) -> Result<(), Box<dyn Error>>
    where
        F: FnOnce() -> Result<(), Box<dyn Error>>,
    {
        self.execute("BEGIN TRANSACTION;")?;

        for query in query_fns {
            match query() {
                Ok(()) => continue,
                Err(error) => {
                    self.execute("ROLLBACK;")?;
                    return Err(error);
                }
            }
        }

        self.execute("COMMIT;")?;
        Ok(())
    }
    fn prepare(&self, sql: &str) -> Result<Statement, Box<dyn Error>> {
        let sql = CString::new(sql)?;
        let mut statement_handle: *mut sqlite3_stmt = null_mut();

        let status = unsafe {
            sqlite3_prepare_v2(
                self.handle,
                sql.as_ptr(),
                -1,
                &raw mut statement_handle,
                null_mut(),
            )
        };

        match status {
            SQLITE_OK => Ok(Statement {
                handle: statement_handle,
            }),
            code => Err(format!(
                "sqlite3_prepare_v2 failed with code {}",
                Self::to_sqlite_err(code, Some(self))
            )
            .into()),
        }
    }

    fn execute(&self, sql: &str) -> Result<(), Box<dyn Error>> {
        let mut statement = self.prepare(sql)?;

        if statement.step()? {
            Err("execute unexpectedly returned a row".into())
        } else {
            Ok(())
        }
    }

    fn insert(&self, sql: &str, binds: &[Bind]) -> Result<(), Box<dyn Error>> {
        let mut statement = self.prepare(sql)?;
        statement.bind_all(binds)?;

        if statement.step()? {
            Err(format!("insertion unexpectedly returned a row {sql}").into())
        } else {
            Ok(())
        }
    }

    // fn insert_rows(&self, sql: &str, multi_binds: Vec<Vec<Bind>>) -> Result<(), Box<dyn Error>> {
    //     self.transaction(|| self.insert_rows_unchecked(sql, multi_binds))
    // }

    fn insert_rows_unchecked(
        &self,
        sql: &str,
        multi_binds: Vec<Vec<Bind>>,
    ) -> Result<(), Box<dyn Error>> {
        let mut statement = self.prepare(sql)?;

        for binds in multi_binds {
            statement.bind_all(&binds)?;

            if statement.step()? {
                return Err(format!("insertion unexpectedly returned a row {sql}").into());
            }

            statement.reset_binds()?;
        }
        Ok(())
    }

    fn querry(
        &self,
        sql: &str,
        binds: &[Bind],
        return_typ: &[ColumnTyp],
    ) -> Result<SqlResult, Box<dyn Error>> {
        let mut statement = self.prepare(sql)?;

        statement.bind_all(binds)?;

        let mut res = vec![vec![]; return_typ.len()];

        while statement.step()? {
            for (i, typ) in return_typ.iter().enumerate() {
                let value = typ.get_from_statement(&statement, i)?;

                res.get_mut(i).expect("invariant").push(value);
            }
        }

        Ok(SqlResult { inner: res })
    }
    pub fn serialize(&self) -> Vec<u8> {
        let serialized_db_size = &mut 0;
        let flags = 0;

        unsafe {
            let serialized_db_ptr =
                sqlite3_serialize(self.handle, null(), serialized_db_size, flags);

            let bytes =
                slice::from_raw_parts(serialized_db_ptr.cast(), (*serialized_db_size) as usize)
                    .to_vec();

            sqlite3_close(serialized_db_ptr.cast_mut().cast());
            bytes
        }
    }

    pub fn deserialize(content: &[u8]) -> Result<Connection, Box<dyn Error>> {
        let content_len = content.len() as u64;

        let buffer = unsafe { sqlite3_malloc64(content_len) }.cast::<u8>();

        unsafe {
            std::ptr::copy_nonoverlapping(content.as_ptr(), buffer, content.len());
        }

        let conn = Connection::open(":memory:")?; // Temp empty db in memory
        let flags = SQLITE_DESERIALIZE_FLAG_FREEONCLOSE | SQLITE_DESERIALIZE_FLAG_RESIZEABLE;

        let status = unsafe {
            sqlite3_deserialize(conn.handle, null(), buffer, content_len, content_len, flags)
        };

        match status {
            SQLITE_OK => Ok(conn),
            code => Err(format!(
                "Deserializing db failed with code {}",
                Self::to_sqlite_err(code, None)
            )
            .into()),
        }
    }

    fn export_db_serialized(&self, path: PathBuf) -> Result<(), Box<dyn Error>> {
        let bytes = self.serialize();

        println!(
            "Exported db of size {} to {path:?}",
            byte_stuff::pretty_bytes(bytes.len())
        );
        fs::write(path, bytes)?;
        Ok(())
    }

    fn import_db(path: PathBuf) -> Result<Connection, Box<dyn Error>> {
        let bytes = fs::read(&path)?;

        let conn = Connection::deserialize(&bytes)?;
        println!(
            "Imported db of size {} from {path:?}",
            byte_stuff::pretty_bytes(bytes.len())
        );

        Ok(conn)
    }

    fn sqlite_error_msg(conn: &Connection) -> String {
        unsafe {
            CStr::from_ptr(sqlite3_errmsg(conn.handle))
                .to_string_lossy()
                .into_owned()
        }
    }

    fn to_sqlite_err(code: i32, conn: Option<&Connection>) -> String {
        match code & 0xff {
            0 => "SQLITE_OK: operation completed successfully",
            1 if conn.is_none() => "SQLITE_ERROR: generic SQL error: {}",
            1 if let Some(conn) = conn => {
                return format!(
                    "SQLITE_ERROR: generic SQL error: {}",
                    Self::sqlite_error_msg(conn)
                );
            }
            2 => "SQLITE_INTERNAL: internal SQLite error",
            5 => "SQLITE_BUSY: database is busy",
            9 => "SQLITE_INTERRUPT: operation was interrupted",
            10 => "SQLITE_IOERR: disk I/O error",
            11 => "SQLITE_CORRUPT: database is corrupted",
            12 => "SQLITE_NOTFOUND: unknown operation or object",
            14 => "SQLITE_CANTOPEN: unable to open database file",
            17 => "SQLITE_SCHEMA: database schema changed",
            18 => "SQLITE_TOOBIG: string or blob is too large",
            19 => "SQLITE_CONSTRAINT: constraint violation",
            20 => "SQLITE_MISMATCH: datatype mismatch",
            21 => "SQLITE_MISUSE: SQLite API used incorrectly",
            25 => "SQLITE_RANGE: bind parameter or column index out of range",
            26 => "SQLITE_NOTADB: file is not a valid SQLite database",
            27 => "SQLITE_NOTICE: SQLite notice",
            28 => "SQLITE_WARNING: SQLite warning",
            100 => "SQLITE_ROW: sqlite3_step produced another row",
            101 => "SQLITE_DONE: sqlite3_step finished",
            _ => return format!("unknown SQLite result code {code}"),
        }
        .to_owned()
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                sqlite3_close(self.handle);
            }

            self.handle = null_mut();
        }
    }
}

#[derive(Debug, Clone)]
pub struct CachedPageHit {
    pub loadtime: i64,
    pub timestamp: i64,
}

#[derive(Debug)]
pub struct Stats {
    pub start_time: String,
    pub pages: Vec<PageMetric>,
}

#[derive(Debug)]
pub struct PageMetric {
    pub page: String,
    pub avg_loadtime: Duration,
    pub count: i64,
}

pub struct Statement {
    pub(crate) handle: *mut sqlite3_stmt,
}

impl Statement {
    fn step(&mut self) -> Result<bool, Box<dyn Error>> {
        let status = unsafe { sqlite3_step(self.handle) };

        match status {
            SQLITE_ROW => Ok(true),
            SQLITE_DONE => Ok(false),
            code => Err(format!(
                "sqlite3_step failed with code {}",
                Connection::to_sqlite_err(code, None)
            )
            .into()),
        }
    }
    fn bind_all(&self, binds: &[Bind]) -> Result<(), Box<dyn Error>> {
        for (i, bind) in binds.iter().enumerate() {
            bind.apply(self, i)?;
        }
        Ok(())
    }

    fn reset_binds(&self) -> Result<(), Box<dyn Error>> {
        let status = unsafe { sqlite3_reset(self.handle) };

        match status {
            SQLITE_OK => Ok(()),
            code => Err(format!(
                "sqlite3_step failed with code {}",
                Connection::to_sqlite_err(code, None)
            )
            .into()),
        }
    }
}

impl Drop for Statement {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                sqlite3_finalize(self.handle);
            }
        }
    }
}

#[derive(Debug)]
enum Bind<'a> {
    Text(&'a str),
    Int(i64),
    Blob(&'a [u8]),
}

impl Bind<'_> {
    fn apply(&self, statement: &Statement, index: usize) -> Result<(), Box<dyn Error>> {
        let statement = statement.handle;
        let index = index as c_int + 1; // Stinky sqlite is 1 indexed
        let status = match self {
            Bind::Text(value) => unsafe {
                sqlite3_bind_text(
                    statement,
                    index,
                    value.as_ptr().cast(),
                    value.len().try_into()?,
                    None,
                )
            },

            Bind::Int(value) => unsafe { sqlite3_bind_int64(statement, index, *value) },
            Bind::Blob(value) => unsafe {
                sqlite3_bind_blob(
                    statement,
                    index,
                    value.as_ptr().cast(),
                    value.len().try_into()?,
                    None,
                )
            },
        };

        match status {
            SQLITE_OK => Ok(()),
            code => Err(format!(
                "binding parameter {index} failed with code {} for {self:?}",
                Connection::to_sqlite_err(code, None)
            )
            .into()),
        }
    }
}

#[derive(Debug)]
struct SqlResult {
    inner: Vec<Vec<ColumnValue>>,
}

impl SqlResult {
    fn get_text_column(&self, idx: usize) -> Result<Vec<String>, Box<dyn Error>> {
        self.inner[idx]
            .iter()
            .map(|v| match v {
                ColumnValue::Text(s) => Ok(s.into()),
                ColumnValue::Null => Err("Null".into()),
                _ => Err("wrong type".into()),
            })
            .collect()
    }

    fn get_int_column(&self, idx: usize) -> Result<Vec<i64>, Box<dyn Error>> {
        self.inner[idx]
            .iter()
            .map(|v| match v {
                ColumnValue::Int(i) => Ok(*i),
                ColumnValue::Null => Err("Null".into()),
                _ => Err("wrong type".into()),
            })
            .collect()
    }

    fn get_blob_column(&self, idx: usize) -> Result<Vec<&[u8]>, Box<dyn Error>> {
        self.inner[idx]
            .iter()
            .map(|v| match v {
                ColumnValue::Blob(b) => Ok(b.as_slice()),
                ColumnValue::Null => Err("Null".into()),
                _ => Err("wrong type".into()),
            })
            .collect()
    }
}

enum ColumnTyp {
    Text,
    Int,
    Blob,
}

#[derive(Debug, Clone)]
enum ColumnValue {
    Text(String),
    Int(i64),
    Blob(Vec<u8>),
    Null,
}

impl ColumnTyp {
    fn get_from_statement(
        &self,
        statement: &Statement,
        column_index: usize,
    ) -> Result<ColumnValue, Box<dyn Error>> {
        let statement = statement.handle;
        let column_index = column_index.try_into()?;
        match self {
            ColumnTyp::Text => {
                let ptr = unsafe { sqlite3_column_text(statement, column_index) };

                if ptr.is_null() {
                    return Ok(ColumnValue::Null);
                }

                let len: usize =
                    unsafe { sqlite3_column_bytes(statement, column_index) }.try_into()?;

                let bytes = unsafe { slice::from_raw_parts(ptr, len) };

                Ok(ColumnValue::Text(str::from_utf8(bytes)?.to_owned()))
            }

            ColumnTyp::Int => Ok(ColumnValue::Int(unsafe {
                sqlite3_column_int64(statement, column_index)
            })),

            ColumnTyp::Blob => {
                let ptr = unsafe { sqlite3_column_blob(statement, column_index) };

                let len: usize =
                    unsafe { sqlite3_column_bytes(statement, column_index) }.try_into()?;

                if len == 0 {
                    return Ok(ColumnValue::Blob(Vec::new()));
                }

                if ptr.is_null() {
                    return Err("null blob pointer".into());
                }

                let bytes = unsafe { slice::from_raw_parts(ptr.cast(), len) };

                Ok(ColumnValue::Blob(bytes.to_vec()))
            }
        }
    }
}
