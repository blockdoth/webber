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

pub struct Connection {
    stream: TcpStream,
    last_polled: Instant,
}

impl PartialEq for Connection {
    fn eq(&self, other: &Self) -> bool {
        self.last_polled == other.last_polled
    }
}

impl Eq for Connection {}
impl PartialOrd for Connection {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.last_polled.partial_cmp(&other.last_polled)
    }
}

impl Ord for Connection {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.last_polled.cmp(&other.last_polled)
    }
}

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

        let polling = false;

        while !SHUTDOWN.load(Ordering::Relaxed) {
            let now = Instant::now();


            let mut connections: BinaryHeap<Connection> = BinaryHeap::new();
            let mut streams: Vec<TcpStream> = vec![];

            let max_streams_handled = 500;
            
            while streams.len() < max_streams_handled {
                match listener.accept() {
                    Ok((mut stream, peer_addr)) => {
                        let now = Instant::now();
                        last_request = now;
                        stream
                            .set_nonblocking(true)
                            .expect("Failed to change blocking mode");
                        // self.handle_request(
                        //     &mut stream,
                        //     &mut router,
                        //     &mut read_buffer,
                        //     &mut template_cache,
                        // )?;
                        streams.push(stream);
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error.into()),
                }
            }

            // println!("connections {}\r", streams.len());

            streams.retain_mut(|mut stream| {
                let request_slice = match Self::read_request(stream, &mut read_buffer)
                {
                    Ok(slice) => slice,
                    Err(IoError::WouldBlock) => return true,
                    Err(IoError::Timeout) => return true,
                    Err(IoError::ConnectionClosed) => return false,
                    Err(IoError::Io(err)) => return false,
                };
                
                self.handle_request(
                    request_slice,
                    stream,
                    &mut router,
                    &mut template_cache,
                ).expect("idk");

                false
            });

            let duration_since_last_request = now.duration_since(last_request);

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

    fn random_samples(len: usize, n: usize) -> Vec<usize> {
        let n = n.min(len);
        let rng = RandomState::new();

        let mut indices: Vec<usize> = (0..len).collect();

        for i in 0..n {
            let j = i + (rng.hash_one(i) as usize % (len - i));
            indices.swap(i, j);
        }

        indices.truncate(n);
        indices.sort_unstable_by(|a, b| b.cmp(a));

        indices
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

    fn read_request<'a>(stream: &mut TcpStream, buffer: &'a mut [u8]) -> Result<&'a [u8], IoError> {
        let start = Instant::now();
        let max_duration = Duration::from_millis(5);
        let mut loops  = 0;
        loop {
            match stream.read(buffer) {
                Ok(0) => return Err(IoError::ConnectionClosed),
                Ok(n) => return {
                    // if loops > 0 {
                    //     println!("Completed in {} loops", loops);
                        
                    // }

                    Ok(&buffer[..n])},
                Err(ref error) if error.kind() == ErrorKind::WouldBlock => {
                    if Instant::now() - start > max_duration{
                        // println!("Timeout after {} loops", loops);
                        
                        return Err(IoError::WouldBlock);
                    }else {
                        std::hint::spin_loop();
                    }
                }
                Err(error) => {
                    println!("[{}] Read {error:?}", stream.peer_addr().unwrap());
                    return Err(IoError::Io(error));
                }
            }
            loops += 1;
        }
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
