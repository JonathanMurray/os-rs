use crate::sys::ProcessHandle;
use crate::util::{FilePermissions, FileType};

type Result<T> = std::result::Result<T, String>;

pub fn run_touch_proc(mut handle: ProcessHandle, args: Vec<String>) {
    match _run_touch_proc(&mut handle, args) {
        Ok(_) => {
            handle.sc_exit(0);
        }
        Err(e) => {
            handle.stdout(format!("Error: {}\n", e)).unwrap();
            handle.sc_exit(1);
        }
    }
}

fn _run_touch_proc(handle: &mut ProcessHandle, args: Vec<String>) -> Result<()> {
    let path = args.get(1).ok_or_else(|| "missing arg".to_owned())?;
    handle.sc_create(path, FileType::Regular, FilePermissions::ReadWrite)?;
    handle.stdout("File created\n")?;
    Ok(())
}
