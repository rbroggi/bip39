mod bip39;

use crate::bip39::default_bip39;
use std::collections::{HashSet, HashMap};
use std::error::Error;
use std::fmt;
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
    #[structopt(about = "Validate a bip39 word map")]
    Validate(ValidateArgs),
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


#[derive(Debug, StructOpt)]
struct ValidateArgs {
    #[structopt(short, long)]
    bip_file: String,
    #[structopt(short, long)]
    key_file: String,
}

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cfg= Bip39Command::from_args();

    match cfg {
        Bip39Command::Generate(gen_config) => generate_words(gen_config),
        Bip39Command::Encrypt(encrypt_config) => encrypt_file(encrypt_config),
        Bip39Command::Decrypt(decrypt_config) => decrypt_file(decrypt_config),
        Bip39Command::Validate(validate_config) => validate_bip39(validate_config),
    }
}

fn validate_bip39(config: ValidateArgs) -> Result<(), Box<dyn Error>> {
    let mut reader = get_reader(&Some(config.bip_file));

    let mut ciphertext = Vec::new();
    reader.read_to_end(&mut ciphertext)?;

    let plaintext = decrypt_content(&ciphertext, get_secure_password)?;

    let custom_bip39 = parse_custom_bip39_content(plaintext)?;

    if custom_bip39.len() != 2048 {
        return Err("Invalid number of words".into());
    }

    let reader = get_reader(&Some(config.key_file));
    // parse the key file, it should have exactly 24 lines and every line should contain a single word which is part of the custom bip39 word map
    let mut key = Vec::new();
    for line in reader.lines() {
        key.push(line?);
    }

    if key.len() != 24 {
        return Err("Invalid number of words in the key file".into());
    }

    let mut raw_key: Vec<u16> = Vec::new();
    for  word in key.iter() {
        let element = custom_bip39.get(word).expect("word not found in the custom bip39 word map");
        raw_key.push(*element);
    }

    // parse raw_key by only considering the first 11 bits of each element into a Vec<u8>
    let key_bytes = parse_u16_to_u8(raw_key)?;

    // see if the key respects checksum
    let mut hasher = Sha256::new();
    hasher.update(&key_bytes[..key_bytes.len() - 1]);
    let hash = hasher.finalize();
    // the checksum is the first 8 bits of the hash
    let checksum = hash[0];
    if checksum != key_bytes[key_bytes.len() - 1] {
        return Err("Invalid checksum".into());
    }

    eprintln!("valid key according to the custom bip39 word map");
    Ok(())
}

// parse a Vec<u16> into a Vec<u8> by considering only the first 11 bits of each element
// considering that every u16 element is a 11 bit number, the total number of bits in the input should be a multiple of 8.
fn parse_u16_to_u8(input: Vec<u16>) -> Result<Vec<u8>, ParseError> {
    if input.len() * 11 % 8 != 0 {
        return Err(ParseError::InvalidInputSize);
    }

    let mut result = Vec::with_capacity(32);
    let mut current_byte = 0u8;
    let mut vacant_bits_in_current_byte = 8;

    for &num in &input {
        let eleven_bits = num & 0x07FF; // Extract the first 11 bits
        // we are going to fill the current_byte one or more times and push it to the result
        let mut remaining_bits_to_consume = 11;
        while remaining_bits_to_consume > 0 {
            // will fill current_byte with min of vacant_bits_in_current_byte and remaining_bits_to_consume
            let to_fill = std::cmp::min(vacant_bits_in_current_byte, remaining_bits_to_consume);
            // extract to_fill bits from eleven_bits
            // 1. consider only bits to the right for remaining bits
            // 2. shift right to exclude all bits that are beyond to_fill
            let mut to_fill_bits = eleven_bits & ((1 << remaining_bits_to_consume) - 1);
            // shifting right to_fill_bits to the right to fill the current_byte
            to_fill_bits = to_fill_bits >> (remaining_bits_to_consume - to_fill);

            // fill the current_byte with to_fill_bits by appending to_fill bites to the right of the vacant bits
            current_byte |= (to_fill_bits << (vacant_bits_in_current_byte - to_fill)) as u8;

            // update the remaining bits to consume and the vacant bits in the current byte
            remaining_bits_to_consume -= to_fill;
            vacant_bits_in_current_byte -= to_fill;
            if vacant_bits_in_current_byte == 0 {
                result.push(current_byte);
                current_byte = 0;
                vacant_bits_in_current_byte = 8;
            }
        }
    }

    Ok(result)
}

fn parse_custom_bip39_content(content: Vec<u8>) -> Result<HashMap<String, u16>, Box<dyn std::error::Error>> {
    let content_str = std::str::from_utf8(&content)?;
    let mut map: HashMap<String, u16> = HashMap::new();

    for line in content_str.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        if words.len() == 4 {
            let key = words[0].to_string();
            let value: u16 = words[3].parse().unwrap_or(0);
            map.insert(key, value);
        }
    }

    Ok(map)
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

#[derive(Debug, PartialEq)]
enum ParseError {
    InvalidInputSize,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::InvalidInputSize => write!(f, "Invalid input size"),
        }
    }
}

impl std::error::Error for ParseError {}

#[cfg(test)]
mod tests {
    use crate::{decrypt_content, encrypt_content, parse_u16_to_u8, ParseError};

    #[test]
    fn encrypt_decrypt() {
        let pwd_provider = || return "a % convoluted $ PWD".to_string();
        let plaintext = b"Some plaintext".to_vec();
        let ciphertext = encrypt_content(&plaintext, pwd_provider).unwrap();
        let got = decrypt_content(&ciphertext, pwd_provider).unwrap();
        assert_eq!(plaintext, got)
    }

    #[test]
    fn test_parse_u16_to_u8() {
        let input: Vec<u16> = vec![
            0b10000000000,
            0b01000000000,
            0b00100000000,
            0b00010000000,
            0b00001000000,
            0b00000100000,
            0b00000010000,
            0b00000001000,
        ];
        let expected = vec![
            0b10000000,
            0b00001000,
            0b00000000,
            0b10000000,
            0b00001000,
            0b00000000,
            0b10000000,
            0b00001000,
            0b00000000,
            0b10000000,
            0b00001000,
        ];
        let got = parse_u16_to_u8(input).unwrap();
        assert_eq!(expected, got);
    }


    #[test]
    fn test_parse_u16_to_u8_err_size() {
        let input: Vec<u16> = vec![
            0b10000000000,
            0b01000000000,
            0b00100000000,
            0b00010000000,
            0b00001000000,
            0b00000100000,
            0b00000010000,
            0b00000001000,
            0b00000000100,
        ];
        let got = parse_u16_to_u8(input);
        assert_eq!(Err(ParseError::InvalidInputSize), got);
    }
}


