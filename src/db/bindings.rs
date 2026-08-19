use std::ffi::{c_char, c_int, c_void};

pub const SQLITE_OK: c_int = 0;
pub const SQLITE_ROW: c_int = 100;
pub const SQLITE_DONE: c_int = 101;

pub const SQLITE_DESERIALIZE_FLAG_FREEONCLOSE: u32 = 1;
pub const SQLITE_DESERIALIZE_FLAG_RESIZEABLE: u32 = 2;

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct sqlite3_stmt {
    _private: [u8; 0],
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct sqlite3_handle {
    _private: [u8; 0],
}

#[allow(non_camel_case_types)]
type sqlite3_destructor = Option<unsafe extern "C" fn(*mut c_void)>;

#[link(name = "sqlite3", kind = "static")]
unsafe extern "C" {
    pub fn sqlite3_open(
        filename: *const c_char,         /* Database filename (UTF-8) */
        pp_db: *mut *mut sqlite3_handle, /* OUT: SQLite db handle */
    ) -> c_int;

    pub fn sqlite3_close(db: *mut sqlite3_handle) -> c_int;
    pub fn sqlite3_prepare_v2(
        db: *mut sqlite3_handle,                  /* Database handle */
        sql: *const c_char,                       /* SQL statement, UTF-8 encoded */
        max_sql_len: c_int,                       /* Maximum length of zSql in bytes. */
        statement_handle: *mut *mut sqlite3_stmt, /* OUT: Statement handle */
        unused_sql: *mut *const c_char,           /* OUT: Pointer to unused portion of zSql */
    ) -> c_int;
    pub fn sqlite3_step(statement_handle: *mut sqlite3_stmt) -> c_int;
    pub fn sqlite3_finalize(statement_handle: *mut sqlite3_stmt) -> c_int;

    pub fn sqlite3_bind_blob(
        statement_handle: *mut sqlite3_stmt,
        index: c_int,
        value: *const c_void,
        value_len: c_int,
        destructor: sqlite3_destructor,
    ) -> c_int;
    pub fn sqlite3_bind_text(
        statement_handle: *mut sqlite3_stmt,
        index: c_int,
        value: *const i8,
        value_len: c_int,
        destructor: sqlite3_destructor,
    ) -> c_int;

    pub fn sqlite3_bind_int64(
        statement_handle: *mut sqlite3_stmt,
        index: c_int,
        value: i64,
    ) -> c_int;

    pub fn sqlite3_column_blob(
        statement_handle: *mut sqlite3_stmt,
        column_index: c_int,
    ) -> *const c_void;
    pub fn sqlite3_column_int64(statement_handle: *mut sqlite3_stmt, column_index: c_int) -> i64;
    pub fn sqlite3_column_text(
        statement_handle: *mut sqlite3_stmt,
        column_index: c_int,
    ) -> *const u8;
    pub fn sqlite3_column_bytes(statement_handle: *mut sqlite3_stmt, column_index: c_int) -> c_int;

    pub fn sqlite3_serialize(
        db: *mut sqlite3_handle, /* The database connection */
        target: *const i8,       /* Which DB to serialize. ex: "main", "temp", ... */
        result_size: *mut u64,   /* Write size of the DB here, if not NULL */
        flags: u32,              /* Zero or more SQLITE_SERIALIZE_* flags */
    ) -> *const u8;

    pub fn sqlite3_deserialize(
        db: *mut sqlite3_handle,  /* The database connection */
        target: *const i8,        /* Which DB to reopen with the deserialization */
        content: *const u8,       /* The serialized database content */
        content_len: u64,         /* Number of bytes in the deserialization */
        content_bufffer_len: u64, /* Total size of content buffer */
        flags: u32,               /* Zero or more SQLITE_SERIALIZE_* flags */
    ) -> c_int;
    pub fn sqlite3_malloc64(size: u64) -> *mut c_void;
    pub fn sqlite3_free(ptr: *mut c_void);
    pub fn sqlite3_errmsg(db: *mut sqlite3_handle) -> *const i8;
    pub fn sqlite3_reset(statement_handle: *mut sqlite3_stmt) -> c_int;
}
