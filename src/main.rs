use std::env;
use bip39::run;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    run(env::args())
}
