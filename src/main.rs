mod devfs;
mod procfs;
mod regularfs;
mod shell;
mod sys;
mod util;
mod vfs;

use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::shell::Shell;
use crate::sys::{ProcessHandle, System, WaitPidOptions, WaitPidTarget, GLOBAL_PROCESS_TABLE};
use crate::util::{FilePermissions, FileType};

#[tokio::main]
pub async fn main() {
    println!("Operating System initializing...");

    let liveness = Arc::new(());

    let sys = System::new();
    let sys = Arc::new(Mutex::new(sys));
    {
        let processes = GLOBAL_PROCESS_TABLE.lock().unwrap();
        let init_handle = System::spawn_process(processes, sys, "init".to_owned(), 0);
        let liveness = Arc::clone(&liveness);
        tokio::task::spawn_blocking(move || run_init_proc(init_handle, liveness))
    };

    loop {
        std::thread::sleep(Duration::from_millis(20));
        {
            let mut spawn_queue = sys::GLOBAL_PROCESS_SPAWN_QUEUE.lock().unwrap();
            if let Some(new_handle) = spawn_queue.pop_back() {
                tokio::task::spawn_blocking(move || run_new_proc(new_handle));
            }
        }
    }
}

fn run_init_proc(mut handle: ProcessHandle, liveness_checker: Arc<()>) {
    handle
        .sc_create("/bin", FileType::Directory, FilePermissions::ReadOnly)
        .unwrap();
    handle
        .sc_create("/bin/script", FileType::Regular, FilePermissions::ReadOnly)
        .unwrap();
    handle
        .sc_create("/bin/sleep", FileType::Regular, FilePermissions::ReadOnly)
        .unwrap();

    handle
        .sc_create(
            "/bin/background",
            FileType::Regular,
            FilePermissions::ReadOnly,
        )
        .unwrap();
    handle
        .sc_create("log", FileType::Regular, FilePermissions::ReadWrite)
        .unwrap();
    let log_fd = handle.sc_open("/dev/log").unwrap();

    handle
        .sc_create("/bin/shell", FileType::Regular, FilePermissions::ReadOnly)
        .unwrap();

    handle
        .sc_spawn("/bin/shell")
        .expect("spawn shell from init");

    handle
        .sc_spawn("/bin/background")
        .expect("spawn background proc from init");

    handle
        .sc_write(log_fd, "Init starting...\n".as_bytes())
        .unwrap();
    loop {
        handle = match handle.handle_signals() {
            Some(handle) => handle,
            None => {
                println!("WARN: Init process was killed");
                return;
            }
        };

        let child_pid = handle
            .sc_spawn("/bin/script")
            .expect("spawn child from init");
        //TODO wait for other children too ('background' task for example)
        let child_result = handle
            .sc_wait_pid(WaitPidTarget::AnyChild, WaitPidOptions::Default)
            .unwrap();
        eprintln!("child wait result: {:?}", child_result);
        handle
            .sc_write(
                log_fd,
                format!("{}: {:?}\n", child_pid, child_result).as_bytes(),
            )
            .unwrap();

        std::thread::sleep(Duration::from_secs(1));
        if Arc::strong_count(&liveness_checker) < 2 {
            break;
        }
    }
    println!("Init process exiting.");
}

fn run_new_proc(mut handle: ProcessHandle) {
    let name = handle.process_name();

    if let Err(err) = handle.sc_stat(&name) {
        eprintln!("did not find {}: {}", name, err);
        handle.sc_exit(1);
        return;
    }

    match name.as_ref() {
        "/bin/script" => run_script_proc(handle),
        "/bin/background" => run_background_proc(handle),
        "/bin/shell" => run_shell_proc(handle),
        "/bin/sleep" => run_sleep_proc(handle),
        _ => {
            eprintln!("Not a valid executable: {}", name);
            handle.sc_exit(2);
        }
    }
}

fn run_sleep_proc(mut handle: ProcessHandle) {
    for _ in 0..5 {
        handle = match handle.handle_signals() {
            Some(handle) => handle,
            None => {
                return;
            }
        };
        std::thread::sleep(Duration::from_millis(500));
    }

    //TODO Don't print directly. Introduce stdout as a proper concept.
    println!("Woke up after sleeping.");

    handle.sc_exit(0);
}

fn run_script_proc(mut handle: ProcessHandle) {
    for _ in 0..5 {
        handle = match handle.handle_signals() {
            Some(handle) => handle,
            None => {
                return;
            }
        };
        std::thread::sleep(Duration::from_secs(1));
    }

    handle.sc_exit(0);
}

fn run_background_proc(mut sys: ProcessHandle) {
    sys.sc_create("README", FileType::Regular, FilePermissions::ReadWrite)
        .expect("Create README file");
    let fd = sys.sc_open("README").expect("Open README file");
    let readme = "Commands:\nstat\ncat\nls\nll\ntouch\nmkdir\ncd\nrm\nmv\nhelp\n";
    sys.sc_write(fd, readme.as_bytes())
        .expect("Write to README");
    sys.sc_close(fd).expect("Close README");

    sys.sc_create("uptime", FileType::Regular, FilePermissions::ReadWrite)
        .expect("Create uptime file");
    let fd = sys.sc_open("uptime").expect("Open uptime file");
    let mut secs = 0_u64;
    for _ in 0..50 {
        sys = match sys.handle_signals() {
            Some(sys) => sys,
            None => {
                return;
            }
        };

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
    sys.sc_close(fd).expect("Close uptime file");
}

fn run_shell_proc(mut sys: ProcessHandle) {
    println!("Welcome!");
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut sh = Shell::new();
    loop {
        let current_dir_name = sys.sc_get_current_dir_name().expect("Must have valid cwd");
        print!("{}$ ", current_dir_name.as_str());
        stdout.flush().unwrap();
        let mut input = String::new();
        stdin.read_line(&mut input).unwrap();
        sh.handle(&mut sys, input);
    }
}
