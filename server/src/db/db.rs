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
use crate::runtime::db::connection::{Bind, ColumnTyp, Connection};
use crate::runtime::misc::byte_stuff::{self};

pub const METRICS_CACHE_SIZE: usize = 5000;
pub const DB_SYNC_INTERVAL: u64 = 120;

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

#[derive(Debug)]
pub struct Db {
    connection: Connection,
    executable_path: PathBuf,
    unsynced: bool,
    metric_cache: HashMap<String, Vec<CachedPageHit>>,
    current_cache_count: usize,
    path_string_intern_cache: HashMap<String, i64>,
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
            path_string_intern_cache: Self::init_path_intern_cache(&conn)?,
            connection: conn,
            executable_path: current_executable_path,
            unsynced: true,
            metric_cache: HashMap::new(),
            current_cache_count: 0,
        };
        // db.sync()?;
        Ok(db)
    }

    pub fn init_path_intern_cache(
        conn: &Connection,
    ) -> Result<HashMap<String, i64>, Box<dyn Error>> {
        let res = conn.querry(
            "SELECT path, id FROM page_path_id_map",
            &[],
            &[ColumnTyp::Text, ColumnTyp::Int],
        )?;

        let keys = res.get_text_column(0)?;
        let values = res.get_int_column(1)?;

        Ok(keys.into_iter().zip(values).collect())
    }

    pub fn sync(&mut self) -> Result<(), Box<dyn Error>> {
        if self.current_cache_count != 0 {
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
                page_id NOT NULL,
                load_time INTEGER NOT NULL,
                timestamp TIMESTAMP NOT NULL
            );",
        )?;
        conn.execute(
            "
            CREATE TABLE page_metrics_aggregate (
                page_id INTEGER PRIMARY KEY,
                total_load_time INTEGER NOT NULL,
                total_hits INTEGER NOT NULL
            );",
        )?;
        conn.execute(
            "
            CREATE TABLE page_path_id_map (
                id INTEGER PRIMARY KEY,
                path TEXT NOT NULL UNIQUE
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

    fn sync_metric_cache(&mut self) -> Result<(), Box<dyn Error>> {
        let conn = &self.connection;

        let page_binds = self
            .metric_cache
            .keys()
            .map(|key| vec![Bind::Text(key)])
            .collect();

        // Update path string intern map
        conn.transaction(|| {
            let res = conn.insert_rows_unchecked_returning(
                "INSERT INTO page_path_id_map (path) VALUES (?) ON CONFLICT(path) DO NOTHING RETURNING path, id",
                page_binds,
                &[ColumnTyp::Text, ColumnTyp::Int]
            )?;

            let keys = res.get_text_column(0)?;
            let values = res.get_int_column(1)?;

            self.path_string_intern_cache.extend(keys.into_iter()
                .zip(values));

            Ok(())
        })?;

        let multi_binds_metrics = self
            .metric_cache
            .iter()
            .flat_map(|(key, hits)| {
                hits.iter().map(|hit| {
                    let id = *self
                        .path_string_intern_cache
                        .get(key)
                        .expect("string intern failure");
                    vec![
                        Bind::Int(id),
                        Bind::Int(hit.loadtime),
                        Bind::Int(hit.timestamp),
                    ]
                })
            })
            .collect();

        let aggregates: Vec<(i64, i64, i64)> = self
            .metric_cache
            .iter()
            .map(|(key, hits)| {
                let total_loadtime = hits.iter().map(|hit| hit.loadtime).sum();
                let count = hits.len() as i64;
                let id = *self
                    .path_string_intern_cache
                    .get(key)
                    .expect("string intern failure");

                (id, total_loadtime, count)
            })
            .collect();

        let multi_binds_metrics_aggregate = aggregates
            .iter()
            .map(|b| vec![Bind::Int(b.0), Bind::Int(b.1), Bind::Int(b.2)])
            .collect();

        conn.transaction(|| {
            conn.insert_rows_unchecked(
                "INSERT INTO page_metrics (page_id, load_time, timestamp) VALUES (?,?,?)",
                multi_binds_metrics,
            )?;
            conn.insert_rows_unchecked(
                "
                INSERT INTO page_metrics_aggregate (
                  page_id,
                  total_load_time,
                  total_hits
                )
                VALUES (?, ?, ?)
                ON CONFLICT(page_id)
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
                SELECT
                    page_path_id_map.path,
                    page_metrics_aggregate.total_load_time,
                    page_metrics_aggregate.total_hits
                FROM page_metrics_aggregate
                JOIN page_path_id_map
                ON page_metrics_aggregate.page_id = page_path_id_map.id;
                ",
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

        metrics.sort_unstable_by(|a, b| b.count.cmp(&a.count));
        Ok(Stats {
            pages: metrics,
            start_time,
        })
    }

    pub fn import_db(path: PathBuf) -> Result<(), Box<dyn Error>> {
        let executable_path = env::current_exe()?;

        let connection = Connection::import_db(path)?;
        let mut db = Db {
            path_string_intern_cache: Self::init_path_intern_cache(&connection)?,
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
        self.sync()?;
        self.connection.export_db_serialized(path)
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
