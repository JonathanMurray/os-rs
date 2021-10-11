use crate::sys::{OpenFlags, ProcessHandle};
use crate::util::{FilePermissions, SysResult};

use std::time::Duration;

pub fn run_background_proc(mut sys: ProcessHandle) {
    let readme = "Commands:\nstat\ncat\nls\nll\ntouch\nmkdir\ncd\nrm\nmv\nhelp\n";
    create_text_file(&mut sys, "README", readme).expect("creating readme");

    let fd = sys
        .sc_open(
            "uptime",
            OpenFlags::WRITE_ONLY | OpenFlags::CREATE,
            Some(FilePermissions::new(7, 4)),
        )
        .expect("Open uptime file");
    eprintln!("background proc opened uptime file with fd: {}", fd);
    let mut secs = 0_u64;
    for _ in 0..50 {
        sys.handle_signals();

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

fn create_text_file(handle: &mut ProcessHandle, path: &str, content: &str) -> SysResult<()> {
    let fd = handle.sc_open(
        path,
        OpenFlags::WRITE_ONLY | OpenFlags::CREATE,
        Some(FilePermissions::new(7, 4)),
    )?;
    //TODO we leak the FD if write fails
    let content = content.as_bytes();
    let n_written = handle.sc_write(fd, content)?;
    assert_eq!(n_written, content.len(), "We didn't writ the whole file");
    handle.sc_close(fd)
}
