use crate::programs::file_helpers::FileReader;
use crate::sys::ProcessHandle;


pub fn run_dump_proc(mut handle: ProcessHandle, args: Vec<String>) {
    match _run_dump_proc(&mut handle, args) {
        Ok(_) => {
            handle.sc_exit(0);
        }
        Err(e) => {
            handle.stdout(format!("Error: {}\n", e)).unwrap();
            handle.sc_exit(1);
        }
    }
}

pub fn _run_dump_proc(handle: &mut ProcessHandle, args: Vec<String>) -> Result<(), String> {
    let path = args.get(1).ok_or_else(|| "Missing path arg".to_owned())?;
    let mut reader =
        FileReader::open(handle, path).map_err(|e| format!("Failed to open {}: {}", path, e))?;

    let mut buf = [0; 1024];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| format!("Failed to read {}: {}", path, e))?;

        let n = n.expect("TODO: handle blocking file read");

        if n == 0 {
            break;
        }

        handle.stdout(format!("{:?}\n", &buf[..n]))?;
    }
    Ok(())
}
