use std::collections::HashMap;
use std::io::{ErrorKind, Read};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::time::Duration;

use std::time::Instant;

use crate::runtime::assets::asset::AssetData;
use crate::runtime::assets::content::Content;
use crate::runtime::db::db::DB_SYNC_INTERVAL;
use crate::runtime::misc::sighandlers::SHUTDOWN;
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

        let mut read_buffer = [0u8; READ_BUFFER_SIZE];
        let mut template_cache = HashMap::new();

        let mut scheduler = Scheduler::new();

        scheduler.schedule_repeating(ScheduledTaskType::SyncDatabase, Duration::from_secs(1));
        #[cfg(debug_assertions)]
        scheduler.schedule_repeating(ScheduledTaskType::UpdateContent, Duration::from_millis(50));

        let mut last_request = Instant::now();
        let mut bounded_average_time_between_requests = Duration::from_millis(5);

        while !SHUTDOWN.load(Ordering::Relaxed) {
            let iter_timer = Instant::now();
            match listener.accept() {
                Ok((stream, peer_addr)) => {
                    let now = Instant::now();
                    let duration_since_last_request = now.duration_since(last_request);
                    last_request = now;

                    bounded_average_time_between_requests = compute_running_average_delay_bounded(
                        bounded_average_time_between_requests,
                        duration_since_last_request,
                        Duration::from_secs(1),
                    );

                    self.handle_connection(
                        stream,
                        peer_addr,
                        &mut router,
                        &mut read_buffer,
                        &mut template_cache,
                    )?;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }

            scheduler.execute_due_tasks_with_budget(
                self,
                &mut router,
                &mut template_cache,
                bounded_average_time_between_requests,
            );

            // print!("{:?}\r", bounded_average_time_between_requests);
            std::hint::spin_loop();
        }

        router.db.sync()?;
        Ok(())
    }

    fn handle_connection(
        &mut self,
        mut stream: TcpStream,
        peer_addr: std::net::SocketAddr,
        router: &mut Router,
        read_buffer: &mut [u8],
        template_cache: &mut HashMap<String, String>,
    ) -> Result<(), ServerError> {
        stream
            .set_nonblocking(true)
            .expect("Failed to change blocking mode");

        let request_slice = match Self::read_request(&mut stream, read_buffer, peer_addr) {
            Ok(n) => n,
            Err(()) => return Ok(()),
        };

        self.handle_request(
            &mut stream,
            peer_addr,
            request_slice,
            router,
            template_cache,
        )
    }

    fn read_request<'a>(
        stream: &mut TcpStream,
        buffer: &'a mut [u8],
        peer_addr: std::net::SocketAddr,
    ) -> Result<&'a [u8], ()> {
        loop {
            match stream.read(buffer) {
                Ok(0) => return Err(()),
                Ok(n) => return Ok(&buffer[..n]),
                Err(ref error) if error.kind() == ErrorKind::WouldBlock => {
                    std::hint::spin_loop();
                }
                Err(error) => {
                    println!("[{peer_addr}] Timed out with {error:?}");
                    return Err(());
                }
            }
        }
    }

    fn handle_request(
        &mut self,
        stream: &mut TcpStream,
        peer_addr: std::net::SocketAddr,
        request: &[u8],
        router: &mut Router,
        template_cache: &mut HashMap<String, String>,
    ) -> Result<(), ServerError> {
        let (header, body) = match Self::parse_request(request) {
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
                    eprintln!("[{peer_addr}] request failed: {err}");
                    return Ok(());
                }
            }
        }

        router
            .db
            .save_page_hit(header.path, start_timer.elapsed())
            .expect("in measure");

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
