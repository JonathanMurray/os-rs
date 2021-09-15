mod procfs;
mod regularfs;
mod shell;
mod sys;
mod util;
mod vfs;

use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::sys::{ProcessHandle, System};
use crate::util::{FilePermissions, FileType};

#[tokio::main]
pub async fn main() {
    println!("Welcome to the Operating System!");

    let liveness = Arc::new(());

    let sys = System::new();
    let sys = Arc::new(Mutex::new(sys));
    let _shell_task = {
        let handle = System::spawn_process(sys.clone(), "shell".to_owned());
        tokio::task::spawn_blocking(move || run_shell_proc(handle))
    };
    let _background_task = {
        let handle = System::spawn_process(sys.clone(), "background".to_owned());
        tokio::task::spawn_blocking(move || run_background_proc(handle))
    };
    let _idle_task = {
        let handle = System::spawn_process(sys, "idle".to_owned());

        let liveness = Arc::clone(&liveness);
        tokio::task::spawn_blocking(move || run_idle_proc(handle, liveness))
    };

    loop {
        std::thread::sleep(Duration::from_secs(1));
        {
            let mut processes = sys::processes();
            if let Some(new_handle) = processes.spawned_but_not_yet_handled.pop_back() {
                tokio::task::spawn_blocking(move || run_script_proc(new_handle));
            }
        }
    }

    //futures::try_join!(shell_task, background_task, idle_task).expect("Kernel crashed");
}

fn run_script_proc(mut handle: ProcessHandle) {
    let name = handle.process_name();
    match name.as_ref() {
        "/bin/script" => {}
        _ => todo!("Handle bad script path"),
    }

    for _ in 0..5 {
        if handle.pending_kill_signal().is_some() {
            //SIGKILL
            break;
            // TODO: exit differently if we get killed than if we run to the end
            // This matters for the parent process that is listening
        }
        std::thread::sleep(Duration::from_secs(1));
    }
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
        if sys.pending_kill_signal().is_some() {
            //SIGKILL
            break;
        }

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

fn run_idle_proc(mut handle: ProcessHandle, liveness_checker: Arc<()>) {
    handle
        .sc_create("/bin", FileType::Directory, FilePermissions::ReadOnly)
        .unwrap();
    handle
        .sc_create("/bin/script", FileType::Regular, FilePermissions::ReadOnly)
        .unwrap();

    loop {
        if handle.pending_kill_signal().is_some() {
            //SIGKILL
            break;
        }

        let child_pid = handle
            .sc_spawn("/bin/script")
            .expect("spawn child from init");
        handle.sc_wait_pid(child_pid).unwrap();

        if Arc::strong_count(&liveness_checker) < 2 {
            break;
        }
    }
}

fn run_shell_proc(mut sys: ProcessHandle) {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    loop {
        let current_dir_name = sys.sc_get_current_dir_name().expect("Must have valid cwd");
        print!("{}$ ", current_dir_name.as_str());
        stdout.flush().unwrap();
        let mut input = String::new();
        stdin.read_line(&mut input).unwrap();
        shell::handle(&mut sys, input);
    }
}
