mod bbs_sign;
mod tbbs_sign;

use std::{
    fs,
    io::{prelude::*, BufReader},
    net::{TcpListener, TcpStream},
};
use std::time::Duration;

const HTML_DIR: &str = "html";

fn main() {
    // bbs_sign::pok_signature_revealed_message();
    bbs_sign::bbs_sign();

    // let mut durations: Vec<u128> = Vec::with_capacity(10);
    // for _ in 0..10 {
    //     let duration = tbbs_sign::signing();
    //     durations.push(duration.as_millis());
    //     println!("Duration: {:?}", duration);
    // }
    // println!("Durations: {:?}", durations);
}

fn handle_connection(mut stream: TcpStream) {
    let buf_reader = BufReader::new(&mut stream);
    let request_line = buf_reader.lines().next().unwrap().unwrap();

    let (status_line, filename) = if request_line == "GET / HTTP/1.1" {
        ("HTTP/1.1 200 OK", "html/hello.html")
    } else {
        ("HTTP/1.1 404 NOT FOUND", "html/404.html")
    };

    let contents = fs::read_to_string(filename).unwrap();
    let length = contents.len();

    let response =
        format!("{status_line}\r\nContent-Length: {length}\r\n\r\n{contents}");

    stream.write_all(response.as_bytes()).unwrap();
}