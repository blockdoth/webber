use std::{
    ffi::c_int,
    sync::atomic::{AtomicBool, Ordering},
};

pub const SIGINT: c_int = 2;
pub const SIGTERM: c_int = 15;
pub const SIG_ERR: c_int = -1;

pub static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_signal(_: c_int) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}
unsafe extern "C" {
    fn signal(signal: c_int, handler: extern "C" fn(c_int)) -> c_int;
}

pub fn register_signal_handlers() {
    unsafe {
        assert_ne!(signal(SIGINT, handle_signal), SIG_ERR);
        assert_ne!(signal(SIGTERM, handle_signal), SIG_ERR);
    }
}
