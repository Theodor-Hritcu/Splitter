use clap::{Arg, Command};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

const BASIC_CHUNK: usize = 1024;

fn main() {
    let matches = Command::new("splitter")
        .version("1.0")
        .author("horoxis")
        .about("Split and unsplit large files.")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .arg(
            Arg::new("chunk_size")
                .short('s')
                .long("size")
                .value_name("SIZE")
                .value_parser(clap::value_parser!(String))
                .help("Sets the chunk size. Examples: 1M, 1G"),
        )
        .subcommand(
            Command::new("split")
                .about("Split a file into smaller parts")
                .arg(
                    Arg::new("file")
                        .required(true)
                        .help("The name of the file to split"),
                ),
        )
        .subcommand(
            Command::new("unsplit")
                .about("Unsplit a file from parts")
                .arg(
                    Arg::new("file")
                        .required(true)
                        .help("The name of the base filename to unsplit"),
                ),
        )
        .get_matches();

    let chunk_size = parse_chunk(matches.get_one::<String>("chunk_size")).unwrap_or(BASIC_CHUNK);

    match matches.subcommand() {
        Some(("split", sub_matches)) => {
            let file_name = sub_matches.get_one::<String>("file").unwrap();
            match split_file(file_name, chunk_size) {
                Ok(_) => println!("File split successfully."),
                Err(e) => eprintln!("Error splitting file: {}", e),
            }
        }
        Some(("unsplit", sub_matches)) => {
            let base_file_name = sub_matches.get_one::<String>("file").unwrap();
            match unsplit_file(base_file_name) {
                Ok(_) => println!("File unsplit successfully."),
                Err(e) => eprintln!("Error unsplitting file: {}", e),
            }
        }
        _ => unreachable!(),
    }
}

fn parse_chunk(size_str: Option<&String>) -> Option<usize> {
    size_str?.parse::<usize>().ok().or_else(|| {
        let size_str = size_str.unwrap();
        let size = size_str
            .trim_end_matches(|c: char| c.is_ascii_alphabetic())
            .parse::<usize>()
            .ok()?;

        match size_str.chars().last()? {
            'b' | 'B' => Some(size),
            'k' | 'K' => Some(size * 1024),
            'm' | 'M' => Some(size * 1024 * 1024),
            'g' | 'G' => Some(size * 1024 * 1024 * 1024),
            _ => None,
        }
    })
}

fn split_file(file_name: &str, chunk_size: usize) -> io::Result<()> {
    let file_path = Path::new(file_name);
    let mut file = File::open(file_path)?;
    let metadata = file.metadata()?;
    let mut total_size = metadata.len() as usize;
    let mut buffer = vec![0; chunk_size];
    let mut part_number = 1;
    let file_base = file_path.file_name().unwrap().to_str().unwrap();

    while total_size > 0 {
        let chunk_size = if total_size < chunk_size {
            total_size
        } else {
            chunk_size
        };
        file.read_exact(&mut buffer[..chunk_size])?;

        let mut hasher = Sha256::new();
        hasher.update(&buffer[..chunk_size]);
        let hash = hasher.finalize();

        let part_filename = format!("{}.part{:04}.split", file_base, part_number);
        let hash_filename = format!("{}.part{:04}.sha256", file_base, part_number);
        let mut part_file = File::create(&part_filename)?;
        part_file.write_all(&buffer[..chunk_size])?;

        let mut hash_file = File::create(&hash_filename)?;
        writeln!(hash_file, "{}", hex::encode(hash))?;

        total_size -= chunk_size;
        part_number += 1;
    }

    Ok(())
}

fn unsplit_file(file_name: &str) -> io::Result<()> {
    let mut part_number = 1;
    let mut parts = Vec::new();
    let mut total_size = 0;

    loop {
        let part_filename = format!("{}.part{:04}.split", file_name, part_number);
        let hash_filename = format!("{}.part{:04}.sha256", file_name, part_number);

        if !Path::new(&part_filename).exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Missing part: {}", part_filename),
            ));
        }

        let mut expected_hash = String::new();
        if let Ok(mut hash_file) = File::open(&hash_filename) {
            hash_file.read_to_string(&mut expected_hash)?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Missing hash file: {}", hash_filename),
            ));
        }

        let mut part_file = File::open(&part_filename)?;
        let mut part_data = Vec::new();
        part_file.read_to_end(&mut part_data)?;
        total_size += part_data.len();
        parts.push(part_data.clone());

        let mut hasher = Sha256::new();
        hasher.update(&part_data);
        let hash = hasher.finalize();
        let hash_string = hex::encode(hash);

        if hash_string != expected_hash.trim() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Corrupted part: {}", part_filename),
            ));
        }

        part_number += 1;

        let next_part_filename = format!("{}.part{:04}.split", file_name, part_number);
        if !Path::new(&next_part_filename).exists() {
            break;
        }
    }

    let output_file_name = format!("reassembled_{}", file_name);
    let mut output_file = File::create(output_file_name.clone())?;

    for part in parts {
        output_file.write_all(&part)?;
    }

    println!("Reassembled {} bytes into {:?}",total_size, output_file_name);
    Ok(())
}