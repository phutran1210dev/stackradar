//! A stand-in HTTP server for tests: answers each request with what `respond` returns
//! for its target (`/path?query`), and records the targets.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

pub struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Reply {
    pub fn json(status: u16, body: serde_json::Value) -> Self {
        Self { status, headers: Vec::new(), body: body.to_string() }
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

pub struct Mock {
    /// `http://127.0.0.1:<port>`
    pub base: String,
    requests: Arc<Mutex<Vec<String>>>,
}

impl Mock {
    /// Serve on a free local port until the test process exits. `respond` gets the
    /// request target and `base`, for links back to the server.
    pub fn start(respond: impl Fn(&str, &str) -> Reply + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a local port");
        let base = format!("http://{}", listener.local_addr().expect("local address"));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (log, server_base) = (requests.clone(), base.clone());
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let Some(target) = read_request(&mut stream) else { continue };
                log.lock().unwrap().push(target.clone());
                let reply = respond(&target, &server_base);
                let mut head = format!(
                    "HTTP/1.1 {} Mock\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n",
                    reply.status,
                    reply.body.len()
                );
                for (name, value) in &reply.headers {
                    head.push_str(&format!("{name}: {value}\r\n"));
                }
                let _ = stream.write_all(format!("{head}\r\n{}", reply.body).as_bytes());
            }
        });
        Self { base, requests }
    }

    /// The targets requested so far, in order.
    pub fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

/// The request line's target, after reading the headers and body.
fn read_request(stream: &mut std::net::TcpStream) -> Option<String> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut length = 0;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        if header.trim().is_empty() {
            break;
        }
        if let Some(v) = header.to_ascii_lowercase().strip_prefix("content-length:") {
            length = v.trim().parse().unwrap_or(0);
        }
    }
    reader.read_exact(&mut vec![0; length]).ok()?;
    line.split_whitespace().nth(1).map(String::from)
}
