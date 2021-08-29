mod sys;

use std::io::{self, Write};
use sys::*;

fn main() {
    let mut sys = System::new();
    sys.create("/README", FileType::Regular, FilePermissions::ReadOnly)
        .unwrap();
    let readme = sys.open("/README").unwrap();
    sys.write(readme, "Hello\nworld\n".as_bytes()).unwrap();
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
            Some(&"stat") => stat(&words, &mut sys),
            Some(&"cat") => cat(&words, &mut sys),
            Some(&"ls") => ls(&mut sys),
            Some(&"touch") => touch(&words, &mut sys),
            Some(&"mkdir") => mkdir(&words, &mut sys),
            Some(&"rm") => rm(&words, &mut sys),
            None => {}
            _ => println!("Unknown command"),
        }
    }
}

fn stat(args: &[&str], sys: &mut System) {
    if let Some(&path) = args.get(1) {
        match sys.stat(path) {
            Ok(stat) => {
                let file_type;
                let permissions = format!(
                    "r{}",
                    if stat.permissions == FilePermissions::ReadWrite {
                        "w"
                    } else {
                        "-"
                    }
                );
                let mut size = "".to_owned();
                match stat.file_type {
                    FileType::Regular => {
                        file_type = "file";
                        size = format!(" {} bytes", stat.size.unwrap());
                    }
                    FileType::Directory => {
                        file_type = "directory";
                    }
                }
                println!("{} {}{}", file_type, permissions, size);
            }
            Err(e) => println!("Error: {}", e),
        }
    } else {
        println!("Error: missing arg");
    }
}

fn cat(args: &[&str], sys: &mut System) {
    if let Some(&path) = args.get(1) {
        match sys.open(&path) {
            Ok(fd) => {
                loop {
                    let mut buf = vec![0, 0, 0];
                    let n = sys.read(fd, &mut buf).unwrap();
                    if n > 0 {
                        let s = String::from_utf8_lossy(&buf);
                        print!("{}", s);
                    } else {
                        break;
                    }
                }
                sys.close(fd).unwrap();
            }
            Err(e) => println!("Error: {}", e),
        }
    } else {
        println!("Error: missing arg");
    }
}

fn ls(sys: &mut System) {
    println!("{}", sys.list_dir("/").unwrap().join(" "));
}

fn touch(args: &[&str], sys: &mut System) {
    if let Some(&path) = args.get(1) {
        match sys.create(path, FileType::Regular, FilePermissions::ReadWrite) {
            Ok(_) => println!("File created"),
            Err(e) => println!("Error: {}", e),
        }
    } else {
        println!("Error: missing arg");
    }
}

fn mkdir(args: &[&str], sys: &mut System) {
    if let Some(&path) = args.get(1) {
        match sys.create(path, FileType::Directory, FilePermissions::ReadWrite) {
            Ok(_) => println!("Directory created"),
            Err(e) => println!("Error: {}", e),
        }
    } else {
        println!("Error: missing arg");
    }
}

fn rm(args: &[&str], sys: &mut System) {
    if let Some(&path) = args.get(1) {
        match sys.remove(path) {
            Ok(_) => println!("File removed"),
            Err(e) => println!("Error: {}", e),
        }
    } else {
        println!("Error: missing arg");
    }
}
