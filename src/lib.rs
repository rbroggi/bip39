mod bip39;

use crate::bip39::default_bip39;
use std::collections::{BTreeSet};
use std::env::Args;
use std::fs::File;
use std::io::{stdin, stdout, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use rand::Rng;
use openssl::symm::{decrypt, encrypt, Cipher};
use clap::{Command, Arg, ArgMatches};
use clap::ArgAction::{Append, SetTrue};
use openssl::rand::rand_bytes;
use termion::raw::IntoRawMode;
use argon2::{
    Argon2
};
use sha2::{Sha256, Digest};

#[derive(Debug)]
struct GenerateConfig {
    input_file: Option<String>,
    output_file: Option<String>,
    encrypt: bool,
}

#[derive(Debug)]
struct EncryptConfig {
    input_file: Option<String>,
    output_file: Option<String>,
}

#[derive(Debug)]
struct DecryptConfig {
    input_file: Option<String>,
    output_file: Option<String>,
}

#[derive(Debug)]
enum Config {
    Generate(GenerateConfig),
    Encrypt(EncryptConfig),
    Decrypt(DecryptConfig),
}

pub fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = parse_configuration_from_args(args)?;
    match cfg {
        Config::Generate(gen_config) => generate_words(gen_config),
        Config::Encrypt(encrypt_config) => encrypt_file(encrypt_config),
        Config::Decrypt(decrypt_config) => decrypt_file(decrypt_config),
    }
}

fn parse_configuration_from_args(args: Args) -> Result<Config, Box<dyn std::error::Error>> {
    let matches: ArgMatches = Command::new("bip39")
        .about("Custom bip39")
        .arg(Arg::new("mode")
            .required(true)
            .index(1)
            .help("Mode of operation (generate, encrypt, decrypt)"))
        .arg(Arg::new("input-file")
            .short('i')
            .long("input-file")
            .action(Append)
            .help("Input file"))
        .arg(Arg::new("output-file")
            .short('o')
            .long("output-file")
            .action(Append)
            .help("Output file"))
        .arg(Arg::new("encrypt-file")
            .short('e')
            .long("encrypt-file")
            .action(SetTrue)
            .help("Encrypt file"))
        .get_matches_from(args);

    let mode: String = matches.get_one::<String>("mode")
        .expect("`mode` is mandatory")
        .to_string();
    let input_file: Option<String> = matches.get_one::<String>("input-file").map(|s| s.clone());
    let output_file: Option<String> = matches.get_one::<String>("output-file").map(|s| s.clone());
    let encrypt = matches.get_flag("encrypt-file");


    match mode.as_str() {
        "generate" => {
            let config = GenerateConfig {
                input_file,
                output_file,
                encrypt,
            };
            Ok(Config::Generate(config))
        }
        "encrypt" => {
            let config = EncryptConfig {
                input_file,
                output_file,
            };
            Ok(Config::Encrypt(config))
        }
        "decrypt" => {
            let config = DecryptConfig {
                input_file,
                output_file,
            };
            Ok(Config::Decrypt(config))
        }
        _ => Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid mode",
        ))),
    }
}

fn generate_words(config: GenerateConfig) -> Result<(), Box<dyn std::error::Error>> {
    let dictionary_file = config.input_file.unwrap_or_else(|| String::from("words.txt"));
    let default_bip39 = default_bip39();
    let sample_size = default_bip39.len(); // Adjust the sample size as needed
    let min_len = 4;
    let max_len = 8;

    let words = read_random_lines(&dictionary_file, sample_size, min_len, max_len)?;

    let mut writer = get_writer(&config.output_file);

    let mut i = 0;
    let mut plaintext = Vec::new();
    for word in words {
        let line = format!("{} {} {:011b} {}\n", word, default_bip39[i], i, i);
        plaintext.append(&mut line.into_bytes());
        i = i + 1;
    }

    if config.encrypt {
        let ciphertext = encrypt_content(&plaintext, get_secure_password)?;
        writer.write_all(&ciphertext)?;
    } else {
        writer.write_all(&plaintext)?;
    }

    Ok(())
}

fn read_random_lines(file_path: &str, sample_size: usize, min_length: usize, max_length: usize) -> Result<BTreeSet<String>, std::io::Error> {
    let mut rng = rand::thread_rng();
    let file = File::open(file_path)?;

    // Get the file size
    let file_size = file.metadata()?.len();

    let mut reader = BufReader::new(file);

    let mut words: BTreeSet<String> = BTreeSet::new();

    while words.len() < sample_size {
        // Generate a random offset within the file
        let random_offset = rng.gen_range(0..file_size);

        // Seek to the random offset
        reader.seek(SeekFrom::Start(random_offset))?;
        let mut discard: Vec<u8> = Vec::new();
        if reader.read_until(b'\n', &mut discard).unwrap() == 0 {
            // Handle end of file
            continue;
        }

        let mut line = String::new();
        if reader.read_line(&mut line).unwrap() == 0 {
            // Handle end of file
            continue;
        }
        line = line.trim().to_string();
        if max_length < line.len() || min_length > line.len() || line.contains('\'') || contains_uppercase(&line) || !only_ascii(&line) {
            continue;
        }
        words.insert(line);
    }

    Ok(words)
}

fn only_ascii(text: &str) -> bool {
    text.chars().all(|c| c.is_ascii())
}

fn contains_uppercase(text: &str) -> bool {
    text.chars().any(|c| c.is_uppercase())
}

fn generate_iv(iv_length: usize) -> Vec<u8> {
    let mut iv = vec![0u8; iv_length];
    rand_bytes(&mut iv).unwrap();
    iv
}

fn generate_salt(pwd: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(pwd.as_bytes());
    hasher.finalize().to_vec()
}

const IV_SIZE: usize = 16;
fn encrypt_file(config: EncryptConfig) -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = get_reader(&config.input_file);
    let mut writer = get_writer(&config.output_file);

    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext)?;

    let ciphertext = encrypt_content(&plaintext, get_secure_password)?;

    writer.write_all(&ciphertext)?;
    Ok(())
}

fn encrypt_content(
    plaintext: &Vec<u8>,
    pwd_provider: fn() -> String,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let password = pwd_provider();
    let encryption_key = derive_key_from_password(&password)?;

    let mut iv = generate_iv(IV_SIZE);

    let mut ciphertext = encrypt(
        Cipher::aes_256_cbc(),
        encryption_key.as_slice(),
        Some(&iv),
        plaintext.as_slice())?;

    ciphertext.append(&mut iv);

    Ok(ciphertext)
}

fn decrypt_file(config: DecryptConfig) -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = get_reader(&config.input_file);
    let mut writer = get_writer(&config.output_file);

    let mut ciphertext = Vec::new();
    reader.read_to_end(&mut ciphertext)?;

    let plaintext = decrypt_content(&ciphertext, get_secure_password)?;
    writer.write_all(&plaintext)?;
    Ok(())
}

fn decrypt_content(ciphertext: &Vec<u8>, pwd_provider: fn() -> String) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let password = pwd_provider();
    let encryption_key = derive_key_from_password(&password)?;

    let iv = &ciphertext[ciphertext.len() - IV_SIZE..];
    let ciphertext = &ciphertext[..ciphertext.len() - IV_SIZE];

    let plaintext = decrypt(Cipher::aes_256_cbc(), &encryption_key, Some(iv), ciphertext)?;
    Ok(plaintext)
}

fn get_reader(file_path: &Option<String>) -> Box<dyn BufRead> {
    match file_path {
        Some(path) => Box::new(BufReader::new(File::open(path).unwrap())),
        None => Box::new(BufReader::new(stdin())),
    }
}

fn get_writer(file_path: &Option<String>) -> Box<dyn Write> {
    match file_path {
        Some(path) => Box::new(BufWriter::new(File::create(path).unwrap())),
        None => Box::new(BufWriter::new(stdout())),
    }
}

fn get_secure_password() -> String {
    let mut stdout = stdout().into_raw_mode().unwrap();
    let stdin = stdin();

    print!("Enter encryption password: ");
    stdout.flush().unwrap();

    let mut password = String::new();
    for c in stdin.bytes() {
        let byte = c.expect("Failed to read char");
        if byte == b'\r' || byte == b'\n' {
            break;
        }
        password.push(char::from(byte));
        print!("*");
        stdout.flush().unwrap();
    }
    println!("");

    password
}

fn derive_key_from_password(password: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let salt = generate_salt(password);
    let argon2 = Argon2::default();
    let mut out = [0u8; 32];
    // Hash password to PHC string ($argon2id$v=19$...)
    if let Err(error) = argon2.hash_password_into(password.as_bytes(), &salt[..], &mut out[..]) {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("argon2 error {}", error.to_string()),
        )));
    }
    Ok(out.to_vec())
}

#[cfg(test)]
mod tests {
    use crate::{decrypt_content, encrypt_content};

    #[test]
    fn encrypt_decrypt() {
        let pwd_provider = || return "a % convoluted $ PWD".to_string();
        let plaintext = b"Some plaintext".to_vec();
        let ciphertext = encrypt_content(&plaintext, pwd_provider).unwrap();
        let got = decrypt_content(&ciphertext, pwd_provider).unwrap();
        assert_eq!(plaintext, got)
    }
}
