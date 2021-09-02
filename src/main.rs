mod sys;

use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use sys::*;

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
    let mut proc = System::spawn_process(sys);
    proc.create("/uptime", FileType::Regular, FilePermissions::ReadWrite)
        .expect("Create uptime file");
    let fd = proc.open("/uptime").expect("Open uptime file");
    let mut secs = 0_u64;
    for _ in 0..5 {
        std::thread::sleep(Duration::from_secs(1));
        secs += 1;
        proc.seek(fd, 0).expect("Seek in uptime file");
        proc.write(
            fd,
            format!("System has been running for {} seconds.\n", secs).as_bytes(),
        )
        .expect("Write to uptime file");
    }
}

fn run_shell(sys: Arc<Mutex<System>>) {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    let mut proc = System::spawn_process(sys);

    loop {
        print!("{}$ ", proc.get_current_dir_name().as_str());
        stdout.flush().unwrap();
        let mut input = String::new();
        stdin.read_line(&mut input).unwrap();
        let words: Vec<&str> = input.split_whitespace().collect();
        match words.get(0) {
            Some(&"stat") => stat(&words, &mut proc),
            Some(&"cat") => cat(&words, &mut proc),
            Some(&"ls") => ls(&words, &mut proc),
            Some(&"touch") => touch(&words, &mut proc),
            Some(&"mkdir") => mkdir(&words, &mut proc),
            Some(&"rm") => rm(&words, &mut proc),
            Some(&"mv") => mv(&words, &mut proc),
            Some(&"cd") => cd(&words, &mut proc),
            None => {}
            _ => println!("Unknown command"),
        }
    }
}

fn stat(args: &[&str], sys: &mut Process) {
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

fn cat(args: &[&str], sys: &mut Process) {
    if let Some(&path) = args.get(1) {
        match sys.open(path) {
            Ok(fd) => {
                loop {
                    let mut buf = vec![0, 0, 0];
                    match sys.read(fd, &mut buf) {
                        Ok(n) => {
                            if n > 0 {
                                let s = String::from_utf8_lossy(&buf);
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
                sys.close(fd).unwrap();
            }
            Err(e) => println!("Error: {}", e),
        }
    } else {
        println!("Error: missing arg");
    }
}

fn ls(args: &[&str], sys: &mut Process) {
    let path: &str = args.get(1).unwrap_or(&".");
    match sys.stat(path) {
        Ok(stat) => {
            if stat.file_type == FileType::Regular {
                println!("{}", path); //TODO
            } else {
                match sys.list_dir(path) {
                    Ok(children) => println!("{}", children.join(" ")),
                    Err(e) => println!("Error: {}", e),
                };
            }
        }
        Err(e) => println!("Error: {}", e),
    }
}

fn touch(args: &[&str], sys: &mut Process) {
    if let Some(&path) = args.get(1) {
        match sys.create(path, FileType::Regular, FilePermissions::ReadWrite) {
            Ok(_) => println!("File created"),
            Err(e) => println!("Error: {}", e),
        }
    } else {
        println!("Error: missing arg");
    }
}

fn mkdir(args: &[&str], sys: &mut Process) {
    if let Some(&path) = args.get(1) {
        match sys.create(path, FileType::Directory, FilePermissions::ReadWrite) {
            Ok(_) => println!("Directory created"),
            Err(e) => println!("Error: {}", e),
        }
    } else {
        println!("Error: missing arg");
    }
}

fn rm(args: &[&str], sys: &mut Process) {
    if let Some(&path) = args.get(1) {
        match sys.remove(path) {
            Ok(_) => println!("File removed"),
            Err(e) => println!("Error: {}", e),
        }
    } else {
        println!("Error: missing arg");
    }
}

fn mv(args: &[&str], sys: &mut Process) {
    if let (Some(&src_path), Some(&dst_path)) = (args.get(1), args.get(2)) {
        match sys.rename(src_path, dst_path) {
            Ok(_) => println!("File moved"),
            Err(e) => println!("Error: {}", e),
        }
    } else {
        println!("Error: missing arg(s)");
    }
}

fn cd(args: &[&str], sys: &mut Process) {
    let result = if let Some(&path) = args.get(1) {
        sys.chdir(path)
    } else {
        sys.chdir("/")
    };
    if let Err(e) = result {
        println!("Error: {}", e);
    }
}
