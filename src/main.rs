mod procfs;
mod regularfs;
mod shell;
mod sys;
mod util;
mod vfs;

use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::sys::*;
use crate::util::*;

#[tokio::main]
pub async fn main() {
    let sys = System::new();
    println!("Welcome to the Operating System!");

    let liveness = Arc::new(());
    let liveness_checker = Arc::clone(&liveness);

    let sys = Arc::new(Mutex::new(sys));
    let sys1 = sys.clone();
    let sys2 = sys.clone();
    let sys3 = sys.clone();
    let shell_task = tokio::task::spawn_blocking(move || run_shell_proc(sys1));
    let background_task = tokio::task::spawn_blocking(move || run_background_proc(sys2));
    let idle_task = tokio::task::spawn_blocking(move || run_idle_proc(sys3, liveness_checker));

    futures::try_join!(shell_task, background_task, idle_task).expect("Kernel crashed");
}

fn run_background_proc(sys: Arc<Mutex<System>>) {
    let mut sys = System::spawn_process(sys, "background".to_owned());

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

fn run_idle_proc(sys: Arc<Mutex<System>>, liveness_checker: Arc<()>) {
    let _proc = System::spawn_process(sys, "idle".to_owned());
    loop {
        std::thread::sleep(Duration::from_secs(5));
        if Arc::strong_count(&liveness_checker) < 2 {
            break;
        }
    }
}

fn run_shell_proc(sys: Arc<Mutex<System>>) {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    let mut sys = System::spawn_process(sys, "shell".to_owned());

    loop {
        let current_dir_name = sys.sc_get_current_dir_name().expect("Must have valid cwd");
        print!("{}$ ", current_dir_name.as_str());
        stdout.flush().unwrap();
        let mut input = String::new();
        stdin.read_line(&mut input).unwrap();
        shell::handle(&mut sys, input);
    }
}
