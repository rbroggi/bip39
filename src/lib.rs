mod bip39;

use crate::bip39::default_bip39;
use std::collections::{HashSet};
use std::fs::File;
use std::io::{stdin, stdout, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use rand::Rng;
use openssl::symm::{decrypt, encrypt, Cipher};
use openssl::rand::rand_bytes;
use argon2::{
    Argon2
};
use sha2::{Sha256, Digest};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "bip39", about = "Generates a custom bip39 word map")]
enum Bip39Command {
    #[structopt(about = "Generate a new random personal bip39 word map")]
    Generate(GenerateArgs),
    #[structopt(about = "Encrypt a file")]
    Encrypt(EncryptArgs),
    #[structopt(about = "Decrypt a file")]
    Decrypt(DecryptArgs),
}

#[derive(Debug, StructOpt)]
struct GenerateArgs {
    #[structopt(short, long)]
    input_file: Option<String>,
    #[structopt(short, long)]
    output_file: Option<String>,
    #[structopt(short, long)]
    encrypt: bool,
}

#[derive(Debug, StructOpt)]
struct EncryptArgs {
    #[structopt(short, long)]
    input_file: Option<String>,
    #[structopt(short, long)]
    output_file: Option<String>,
}

#[derive(Debug, StructOpt)]
struct DecryptArgs {
    #[structopt(short, long)]
    input_file: Option<String>,
    #[structopt(short, long)]
    output_file: Option<String>,
}

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cfg= Bip39Command::from_args();

    match cfg {
        Bip39Command::Generate(gen_config) => generate_words(gen_config),
        Bip39Command::Encrypt(encrypt_config) => encrypt_file(encrypt_config),
        Bip39Command::Decrypt(decrypt_config) => decrypt_file(decrypt_config),
    }
}

fn generate_words(config: GenerateArgs) -> Result<(), Box<dyn std::error::Error>> {
    let dictionary_file = config.input_file.unwrap_or_else(|| String::from("words.txt"));
    let default_bip39 = default_bip39();
    let sample_size = default_bip39.len(); // Adjust the sample size as needed
    let min_len = 4;
    let max_len = 8;

    let words = read_random_lines(&dictionary_file, sample_size, min_len, max_len)?;

    let mut writer = get_writer(&config.output_file);

    let mut plaintext = Vec::new();
    for (i, word) in words.into_iter().enumerate() {
        let line = format!("{} {} {:011b} {}\n", word, default_bip39[i], i, i);
        plaintext.append(&mut line.into_bytes());
    }

    if config.encrypt {
        let ciphertext = encrypt_content(&plaintext, get_secure_password)?;
        writer.write_all(&ciphertext)?;
    } else {
        writer.write_all(&plaintext)?;
    }

    Ok(())
}

fn read_random_lines(file_path: &str, sample_size: usize, min_length: usize, max_length: usize) -> Result<HashSet<String>, std::io::Error> {
    let mut rng = rand::thread_rng();
    let file = File::open(file_path)?;

    // Get the file size
    let file_size = file.metadata()?.len();

    let mut reader = BufReader::new(file);

    let mut words: HashSet<String> = HashSet::new();

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
        if max_length < line.len() || min_length > line.len() || line.contains('\'') || contains_uppercase(&line) || !only_ascii(&line) || line.is_empty() {
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
fn encrypt_file(config: EncryptArgs) -> Result<(), Box<dyn std::error::Error>> {
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

fn decrypt_file(config: DecryptArgs) -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = get_reader(&config.input_file);
    let mut writer = get_writer(&config.output_file);

    let mut ciphertext = Vec::new();
    reader.read_to_end(&mut ciphertext)?;

    let plaintext = decrypt_content(&ciphertext, get_secure_password)?;
    writer.write_all(&plaintext)?;
    Ok(())
}

fn decrypt_content(ciphertext: &[u8], pwd_provider: fn() -> String) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
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
    rpassword::prompt_password("enter password: ").unwrap()
}

fn derive_key_from_password(password: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let salt = generate_salt(password);
    let argon2 = Argon2::default();
    let mut out = [0u8; 32];
    // Hash password to PHC string ($argon2id$v=19$...)
    if let Err(error) = argon2.hash_password_into(password.as_bytes(), &salt[..], &mut out[..]) {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("argon2 error {}", error),
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
