use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::collections::HashMap;
use std::error::Error;
use std::hash::BuildHasher;
use std::hash::RandomState;
use std::io::{ErrorKind, Read};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;
use std::vec;

use crate::runtime::assets::asset::AssetData;
use crate::runtime::assets::content::Content;
use crate::runtime::db::connection;
use crate::runtime::db::db::DB_SYNC_INTERVAL;
use crate::runtime::misc::sighandlers::SHUTDOWN;
use crate::runtime::server::error::IoError;
use crate::runtime::server::error::{HttpResponseCode, HttpServerError};
use crate::runtime::server::server::HttpRequestHeader;
use crate::runtime::server::timer_queue::{
    ScheduledTaskType, Scheduler, compute_running_average_delay_bounded,
};
use crate::runtime::server::{error::ServerError, router::Router, server::HttpServer};

const READ_BUFFER_SIZE: usize = 8192;

impl HttpServer {
    pub fn serve(&mut self, listener: TcpListener, mut router: Router) -> Result<(), ServerError> {
        listener
            .set_nonblocking(true)
            .expect("Unable to set socket to nonblocking mode");
        Self::set_backlog(&listener, 4096)?;
        Self::increase_max_fds();

        let mut read_buffer = [0u8; READ_BUFFER_SIZE];
        let mut template_cache = HashMap::new();

        let mut scheduler = Scheduler::new();

        scheduler.schedule_repeating(ScheduledTaskType::SyncDatabase, Duration::from_secs(1));
        #[cfg(debug_assertions)]
        scheduler.schedule_repeating(ScheduledTaskType::UpdateContent, Duration::from_millis(50));
        scheduler.schedule_daily(ScheduledTaskType::UpdateNow, 0, 0);

        let mut last_request = Instant::now();
        let mut average_time_between_requests = Duration::from_secs(1);

        let accept_division = 0.1;
        let time_slice = Duration::from_millis(10);

        let max_accept_time = time_slice.mul_f64(accept_division);
        let max_handle_time = time_slice.mul_f64(1.0 - accept_division);

        let mut connections: BinaryHeap<Reverse<Connection>> = BinaryHeap::new();
        while !SHUTDOWN.load(Ordering::Relaxed) {
            let start_loop_iter = Instant::now();

            while start_loop_iter.elapsed() < max_accept_time {
                match listener.accept() {
                    Ok((mut stream, peer_addr)) => {
                        let now = Instant::now();
                        last_request = now;
                        stream
                            .set_nonblocking(true)
                            .expect("Failed to change blocking mode");

                        connections.push(Reverse(Connection::new(stream)));
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error.into()),
                }
            }

            while start_loop_iter.elapsed() < max_handle_time {
                if let Some(Reverse(mut conn)) = connections.pop() {
                    let request_slice = match Self::read_request(&mut conn.stream, &mut read_buffer)
                    {
                        Ok(slice) => slice,
                        Err(IoError::WouldBlock) => {
                            conn.polled();
                            connections.push(Reverse(conn));
                            continue;
                        }
                        Err(IoError::ConnectionClosed) => continue,
                        Err(IoError::Io(err)) => {
                            println!("{err:?}");
                            continue;
                        }
                    };

                    self.handle_request(
                        request_slice,
                        &mut conn.stream,
                        &mut router,
                        &mut template_cache,
                    )?;
                } else {
                    break;
                }
            }

            let duration_since_last_request = start_loop_iter.duration_since(last_request);

            average_time_between_requests = compute_running_average_delay_bounded(
                average_time_between_requests,
                duration_since_last_request,
                Duration::from_secs(1),
            );
            scheduler.execute_due_tasks_with_budget(
                self,
                &mut router,
                &mut template_cache,
                average_time_between_requests,
            )?;

            // print!("{:?}\r", bounded_average_time_between_requests);
            std::hint::spin_loop();
        }

        router.db.sync()?;
        Ok(())
    }

    fn read_request<'a>(stream: &mut TcpStream, buffer: &'a mut [u8]) -> Result<&'a [u8], IoError> {
        match stream.read(buffer) {
            Ok(0) => Err(IoError::ConnectionClosed),
            Ok(n) => Ok(&buffer[..n]),
            Err(ref error) if error.kind() == ErrorKind::WouldBlock => Err(IoError::WouldBlock),
            Err(error) => {
                println!("[{}] Read {error:?}", stream.peer_addr().unwrap());
                Err(IoError::Io(error))
            }
        }
    }

    fn handle_request(
        &mut self,
        request_slice: &[u8],
        stream: &mut TcpStream,
        router: &mut Router,
        template_cache: &mut HashMap<String, String>,
    ) -> Result<(), ServerError> {
        let (header, body) = match Self::parse_request(request_slice) {
            Ok(request) => request,
            Err(err) => {
                eprintln!("Failed to parse request: {err}");
                return Ok(());
            }
        };

        #[cfg(debug_assertions)]
        if header.path == "/ws" {
            self.upgrade_websocket(header, stream)?;
            self.active_streams.push(stream.try_clone()?);
            return Ok(());
        }

        let start_timer = Instant::now();

        let result = self.route_request(&header, body, stream, router, template_cache);

        if let Err(err) = result {
            match err {
                HttpServerError::StreamWriteFailed(ref io_err)
                    if matches!(
                        io_err.kind(),
                        ErrorKind::BrokenPipe
                            | ErrorKind::ConnectionReset
                            | ErrorKind::ConnectionAborted
                    ) =>
                {
                    return Ok(());
                }

                err => {
                    eprintln!("[{}] request failed: {err}", stream.peer_addr().unwrap());
                    return Ok(());
                }
            }
        }

        router
            .db
            .save_page_hit(header.path, start_timer.elapsed())?;

        Ok(())
    }

    fn route_request(
        &mut self,
        header: &HttpRequestHeader,
        body: AssetData,
        stream: &mut TcpStream,
        router: &mut Router,
        template_cache: &mut HashMap<String, String>,
    ) -> Result<(), HttpServerError> {
        let path = header.path;

        if path.starts_with("/api") {
            return match router.serve_api(header, body) {
                Ok(content) => Self::send_response(
                    HttpResponseCode::Ok,
                    content.as_ref(),
                    &mut self.response_buffer,
                    stream,
                ),
                Err(err) => self.build_error_response(router, err, stream),
            };
        }

        let asset_path = format!("{}{}", router.asset_path, path);

        if let Some(asset) = router.content.assets.get_ref(&asset_path)
            && !asset.internal
        {
            return Self::send_response(
                HttpResponseCode::Ok,
                asset.data.as_ref(),
                &mut self.response_buffer,
                stream,
            );
        }

        match router.serve_page(header, body, &mut self.render_buffer, template_cache) {
            Ok(content) => Self::send_response(
                HttpResponseCode::Ok,
                content,
                &mut self.response_buffer,
                stream,
            ),
            Err(err) => self.build_error_response(router, err, stream),
        }
    }

    fn sync_database(
        &mut self,
        router: &mut Router,
        timer: &mut Instant,
    ) -> Result<(), ServerError> {
        if timer.elapsed() > Duration::from_secs(DB_SYNC_INTERVAL) {
            router.db.sync()?;
            *timer = Instant::now();
        }

        Ok(())
    }

    #[cfg(debug_assertions)]
    pub fn reload_websockets(&mut self) {
        self.active_streams.retain(|mut stream| {
            let alive = match stream.peek(&mut [0]) {
                Ok(0) => false,
                Ok(_) => true,
                Err(ref error) if error.kind() == ErrorKind::WouldBlock => true,
                _ => false,
            };

            if alive {
                let _ = HttpServer::send_ws_message(stream, "reload");
                true
            } else {
                let _ = stream.shutdown(Shutdown::Both);
                false
            }
        });
    }
}

pub struct Connection {
    stream: TcpStream,
    last_polled: Option<Instant>,
    polled_count: u64,
}

impl Connection {
    pub fn new(stream: TcpStream) -> Self {
        Connection {
            stream,
            last_polled: None,
            polled_count: 0,
        }
    }

    pub fn polled(&mut self) {
        self.last_polled = Some(Instant::now());
        self.polled_count += 1;
    }

    fn priority(&self) -> Option<Instant> {
        self.last_polled.map(|last| {
            last - Duration::from_millis(self.polled_count) // Some heuristic
        })
    }
}

impl PartialEq for Connection {
    fn eq(&self, other: &Self) -> bool {
        self.last_polled == other.last_polled && self.polled_count == other.polled_count
    }
}

impl Eq for Connection {}
impl PartialOrd for Connection {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Connection {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority().cmp(&other.priority())
    }
}
