mod core;
mod procfs;
mod regularfs;
mod sys;

use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::core::*;
use crate::sys::*;

#[tokio::main]
pub async fn main() {
    let sys = System::new();
    println!("Welcome to the Operating System!");

    let sys = Arc::new(Mutex::new(sys));
    let sys2 = sys.clone();
    let shell_task = tokio::task::spawn_blocking(move || run_shell(sys2));
    let background_task = tokio::task::spawn_blocking(move || run_background_proc(sys));

    futures::try_join!(shell_task, background_task).expect("Joining futures");
}

fn run_background_proc(sys: Arc<Mutex<System>>) {
    let mut sys = System::spawn_process(sys, "background".to_owned());

    let fd = {
        sys.sc_create("/uptime", FileType::Regular, FilePermissions::ReadWrite)
            .expect("Create uptime file");

        sys.sc_open("/uptime").expect("Open uptime file")
    };
    let mut secs = 0_u64;
    for _ in 0..50 {
        std::thread::sleep(Duration::from_secs(1));
        secs += 1;
        {
            sys.sc_seek(fd, 0).expect("seek in uptime file");
            sys.sc_write(
                fd,
                format!("System has been running for {} seconds.\n", secs).as_bytes(),
            )
            .expect("Write to uptime file");
        }
    }
}

fn run_shell(sys: Arc<Mutex<System>>) {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    let mut sys = System::spawn_process(sys, "shell".to_owned());

    loop {
        {
            let current_dir_name = sys.sc_get_current_dir_name().expect("Must have valid cwd");
            print!("{}$ ", current_dir_name.as_str());
        }
        stdout.flush().unwrap();
        let mut input = String::new();
        stdin.read_line(&mut input).unwrap();
        let words: Vec<&str> = input.split_whitespace().collect();
        {
            match words.get(0) {
                Some(&"stat") => stat(&words, &mut sys),
                Some(&"cat") => cat(&words, &mut sys),
                Some(&"ls") => ls(&words, &mut sys),
                Some(&"touch") => touch(&words, &mut sys),
                Some(&"mkdir") => mkdir(&words, &mut sys),
                Some(&"rm") => rm(&words, &mut sys),
                Some(&"mv") => mv(&words, &mut sys),
                Some(&"cd") => cd(&words, &mut sys),
                None => {}
                _ => println!("Unknown command"),
            }
        }
    }
}

fn stat(args: &[&str], sys: &mut Context) {
    if let Some(&path) = args.get(1) {
        match sys.sc_stat(path) {
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
                        size = format!(" {} bytes", stat.size);
                    }
                    FileType::Directory => {
                        file_type = "directory";
                    }
                }

                println!(
                    "{} {}{} ({}/{})",
                    file_type, permissions, size, stat.filesystem, stat.inode_number
                );
            }
            Err(e) => println!("Error: {}", e),
        }
    } else {
        println!("Error: missing arg");
    }
}

fn cat(args: &[&str], sys: &mut Context) {
    if let Some(&path) = args.get(1) {
        match sys.sc_open(path) {
            Ok(fd) => {
                let mut buf = vec![0; 1024];
                loop {
                    match sys.sc_read(fd, &mut buf) {
                        Ok(n) => {
                            if n > 0 {
                                let s = String::from_utf8_lossy(&buf[..n]);
                                print!("{}", s);
                            } else {
                                break;
                            }
                        }
                        Err(e) => {
                            println!("Error: {}", e);
                            break;
                        }
                    }
                }
                sys.sc_close(fd).unwrap();
            }
            Err(e) => println!("Error: {}", e),
        }
    } else {
        println!("Error: missing arg");
    }
}

fn ls(args: &[&str], sys: &mut Context) {
    let path: &str = args.get(1).unwrap_or(&".");
    match sys.sc_stat(path) {
        Ok(stat) => {
            if stat.file_type == FileType::Regular {
                println!("{}", path); //TODO
            } else {
                match sys.sc_list_dir(path) {
                    Ok(children) => println!("{}", children.join("\t\t")),
                    Err(e) => println!("Error: {}", e),
                };
            }
        }
        Err(e) => println!("Error: {}", e),
    }
}

fn touch(args: &[&str], sys: &mut Context) {
    if let Some(&path) = args.get(1) {
        match sys.sc_create(path, FileType::Regular, FilePermissions::ReadWrite) {
            Ok(_) => println!("File created"),
            Err(e) => println!("Error: {}", e),
        }
    } else {
        println!("Error: missing arg");
    }
}

fn mkdir(args: &[&str], sys: &mut Context) {
    if let Some(&path) = args.get(1) {
        match sys.sc_create(path, FileType::Directory, FilePermissions::ReadWrite) {
            Ok(_) => println!("Directory created"),
            Err(e) => println!("Error: {}", e),
        }
    } else {
        println!("Error: missing arg");
    }
}

fn cd(args: &[&str], sys: &mut Context) {
    let result = if let Some(&path) = args.get(1) {
        sys.sc_chdir(path)
    } else {
        sys.sc_chdir("/")
    };
    if let Err(e) = result {
        println!("Error: {}", e);
    }
}

fn rm(args: &[&str], sys: &mut Context) {
    if let Some(&path) = args.get(1) {
        match sys.sc_remove(path) {
            Ok(_) => println!("File removed"),
            Err(e) => println!("Error: {}", e),
        }
    } else {
        println!("Error: missing arg");
    }
}

fn mv(args: &[&str], sys: &mut Context) {
    if let (Some(&src_path), Some(&dst_path)) = (args.get(1), args.get(2)) {
        match sys.sc_rename(src_path, dst_path) {
            Ok(_) => println!("File moved"),
            Err(e) => println!("Error: {}", e),
        }
    } else {
        println!("Error: missing arg(s)");
    }
}
