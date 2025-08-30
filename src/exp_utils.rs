use ark_bls12_381::{Bls12_381, Fr};
use ark_std::UniformRand;
use bbs_plus::prelude::{KeypairG2, SignatureParams23G1};
use rand::RngCore;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub fn get_as_millis(duration: Duration) -> f64 {
    return duration.as_secs_f64() * 1000.0;
}

// Struct to manage the timer
pub struct Timer {
    label: Option<String>,
    start_time: Arc<Mutex<Option<Instant>>>,
    duration: Arc<Mutex<Option<f64>>>,
}

impl Timer {
    // Creates a new timer
    pub fn new() -> Self {
        Timer {
            label: None,
            start_time: Arc::new(Mutex::new(None)),
            duration: Arc::new(Mutex::new(None)),
        }
    }

    pub fn with_label<L: Into<String>>(label: L) -> Self {
        Timer {
            label: Some(label.into()),
            start_time: Arc::new(Mutex::new(None)),
            duration: Arc::new(Mutex::new(None)),
        }
    }

    // Starts the timer in a separate thread
    pub fn start(&self) {
        let start_time = Arc::clone(&self.start_time);
        thread::spawn(move || {
            let mut time = start_time.lock().unwrap();
            *time = Some(Instant::now());
        });
    }

    // Stops the timer and returns the elapsed time
    pub fn stop(&self) -> Option<Duration> {
        let mut time = self.start_time.lock().unwrap();
        if let Some(start_time) = *time {
            let elapsed = start_time.elapsed();
            *time = None; // Reset the timer
            self.duration
                .lock()
                .unwrap()
                .replace(get_as_millis(elapsed));
            Some(elapsed)
        } else {
            None // Timer was not started
        }
    }

    pub fn stop_and_print_ms(&self) {
        self.stop().map(|d| {
            let ms = get_as_millis(d);
            if let Some(label) = &self.label {
                println!("{}: {:.2} ms", label, ms);
            } else {
                println!("{:.2} ms", ms);
            }
            self.duration.lock().unwrap().replace(ms);
        });
    }

    pub fn get_duration(&self) -> f64 {
        let duration = self.duration.lock().unwrap();
        duration.unwrap_or(0.0)
    }

    pub fn reset(&self) {
        let mut time = self.start_time.lock().unwrap();
        *time = None;
        let mut duration = self.duration.lock().unwrap();
        *duration = None;
    }
}

pub fn measure_time<T, F>(operation: F) -> (T, std::time::Duration)
where
    F: FnOnce() -> T,
{
    let start = Instant::now();
    let result = operation();
    let elapsed = start.elapsed();
    (result, elapsed)
}

pub fn setup_messages<R: rand::RngCore>(rng: &mut R, message_count: u32) -> Vec<Fr> {
    let messages: Vec<Fr> = (0..message_count).map(|_| Fr::rand(rng)).collect();
    return messages;
}

pub fn reveal_messages(
    messages: Vec<Fr>,
    revealed_indices: BTreeSet<usize>,
) -> BTreeMap<usize, Fr> {
    // let mut revealed_indices = BTreeSet::new();
    // revealed_indices.insert(0);
    // revealed_indices.insert(2);
    let mut revealed_msgs = BTreeMap::new();
    for i in revealed_indices.iter() {
        revealed_msgs.insert(*i, messages[*i]);
    }
    return revealed_msgs;
}

pub fn sig_setup<R: RngCore>(
    rng: &mut R,
    message_count: u32,
) -> (
    Vec<Fr>,
    SignatureParams23G1<Bls12_381>,
    KeypairG2<Bls12_381>,
) {
    let messages: Vec<Fr> = (0..message_count).map(|_| Fr::rand(rng)).collect();
    let params = SignatureParams23G1::<Bls12_381>::generate_using_rng(rng, message_count);
    let keypair = KeypairG2::<Bls12_381>::generate_using_rng_and_bbs23_params(rng, &params);
    // let sig = Signature23G1::<Bls12_381>::new(rng, &messages, &keypair.secret_key, &params).unwrap();
    (messages, params, keypair)
}
