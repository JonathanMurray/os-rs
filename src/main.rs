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
    println!("Operating System initializing...");

    let liveness = Arc::new(());

    let sys = System::new();
    let sys = Arc::new(Mutex::new(sys));
    let init_handle = System::spawn_process(sys, "init".to_owned(), 0);
    {
        let liveness = Arc::clone(&liveness);
        tokio::task::spawn_blocking(move || run_init_proc(init_handle, liveness))
    };

    loop {
        std::thread::sleep(Duration::from_millis(20));
        {
            let mut processes = sys::processes();
            if let Some(new_handle) = processes.spawned_but_not_yet_handled.pop_back() {
                tokio::task::spawn_blocking(move || run_new_proc(new_handle));
            }
        }
    }

    //futures::try_join!(shell_task, background_task, idle_task).expect("Kernel crashed");
}

fn run_init_proc(mut handle: ProcessHandle, liveness_checker: Arc<()>) {
    handle
        .sc_create("/bin", FileType::Directory, FilePermissions::ReadOnly)
        .unwrap();
    handle
        .sc_create("/bin/script", FileType::Regular, FilePermissions::ReadOnly)
        .unwrap();
    handle
        .sc_create(
            "/bin/background",
            FileType::Regular,
            FilePermissions::ReadOnly,
        )
        .unwrap();
    handle
        .sc_create("/bin/shell", FileType::Regular, FilePermissions::ReadOnly)
        .unwrap();

    handle
        .sc_spawn("/bin/shell")
        .expect("spawn shell from init");
    handle
        .sc_spawn("/bin/background")
        .expect("spawn background proc from init");

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

fn run_new_proc(mut handle: ProcessHandle) {
    let name = handle.process_name();
    match name.as_ref() {
        "/bin/script" => run_script_proc(handle),
        "/bin/background" => run_background_proc(handle),
        "/bin/shell" => run_shell_proc(handle),
        _ => todo!("Handle bad script path"),
    }
}

fn run_script_proc(mut handle: ProcessHandle) {
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

fn run_shell_proc(mut sys: ProcessHandle) {
    println!("Welcome!");
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
