mod sys;

use std::io::{self, Read, Write};
use sys::*;

fn main() {
    let mut sys = System::new();
    sys.create("/README", FileType::Regular).unwrap();
    let readme = sys.open("/README").unwrap();
    sys.write(readme, "Hello\nworld".as_bytes()).unwrap();
    sys.close(readme).unwrap();
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    loop {
        print!("> ");
        stdout.flush().unwrap();
        let mut input = String::new();
        stdin.read_line(&mut input).unwrap();
        let words: Vec<&str> = input.split_whitespace().collect();
        match words.get(0) {
            Some(&"stat") => stat(&words, &sys),
            Some(&"cat") => cat(&words, &mut sys),
            Some(&"ls") => ls(&sys),
            Some(&"touch") => touch(&words, &mut sys),
            Some(&"mkdir") => mkdir(&words, &mut sys),
            None => {}
            _ => println!("Unknown command"),
        }
    }
}

fn stat(args: &[&str], sys: &System) {
    if let Some(&path) = args.get(1) {
        match sys.stat(path) {
            Ok(FileStat {
                file_type: FileType::Regular,
                size,
            }) => println!("file, {} bytes", size.unwrap()),
            Ok(_) => println!("directory"),
            Err(e) => println!("Error: {}", e),
        }
    } else {
        println!("Error: missing arg");
    }
}

fn cat(args: &[&str], sys: &mut System) {
    if let Some(&path) = args.get(1) {
        match sys.open(&path) {
            Ok(fd) => loop {
                let mut buf = vec![0, 0, 0];
                let n = sys.read(fd, &mut buf).unwrap();
                if n > 0 {
                    let s = String::from_utf8_lossy(&buf);
                    print!("{}", s);
                } else {
                    println!("");
                    break;
                }
            },
            Err(e) => println!("Error: {}", e),
        }
    } else {
        println!("Error: missing arg");
    }
}

fn ls(sys: &System) {
    println!("{}", sys.list_dir("/").unwrap().join(" "));
}

fn touch(args: &[&str], sys: &mut System) {
    if let Some(&path) = args.get(1) {
        match sys.create(path, FileType::Regular) {
            Ok(_) => println!("File created"),
            Err(e) => println!("Error: {}", e),
        }
    } else {
        println!("Error: missing arg");
    }
}

fn mkdir(args: &[&str], sys: &mut System) {
    if let Some(&path) = args.get(1) {
        let path: &str = args.get(1).unwrap();
        match sys.create(path, FileType::Directory) {
            Ok(_) => println!("Directory created"),
            Err(e) => println!("Error: {}", e),
        }
    } else {
        println!("Error: missing arg");
    }
}
