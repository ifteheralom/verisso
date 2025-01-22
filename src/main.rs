mod bbs_sign;
mod tbbs_sign;
mod ot;
mod exp_utils;

const HTML_DIR: &str = "html";

fn main() {
    bbs_sign::test_credential();
    tbbs_sign::test_token();

    // let mut durations: Vec<u128> = Vec::with_capacity(10);
    // for _ in 0..1 {
    //     let duration = bbs_sign::test_signing();
    //     durations.push(duration);
    //     println!("Duration: {:?}", duration);
    // }
    // println!("Durations: {:?}", durations);
}