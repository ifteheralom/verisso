mod bbs_sign;
mod tbbs_sign;
mod ot;
mod exp_utils;

const HTML_DIR: &str = "html";

fn main() {
    bbs_sign::signing();

    // let mut durations: Vec<u128> = Vec::with_capacity(10);
    // for _ in 0..10 {
    //     let duration = tbbs_sign::signing();
    //     durations.push(duration.as_millis());
    //     println!("Duration: {:?}", duration);
    // }
    // println!("Durations: {:?}", durations);
}