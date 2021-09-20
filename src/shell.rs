use crate::sys::{ProcessHandle, ProcessResult, WaitPidOptions, WaitPidTarget};
use crate::util::{FilePermissions, FileStat, FileType, Pid};
use std::str::FromStr;

type Result<T> = core::result::Result<T, String>;

pub struct Shell {
    background_processes: Vec<Pid>,
}

impl Shell {
    pub fn new() -> Self {
        Self {
            background_processes: Default::default(),
        }
    }

    pub fn handle(&mut self, handle: &mut ProcessHandle, input: String) {
        let words: Vec<&str> = input.split_whitespace().collect();
        let result = match words.get(0) {
            Some(&"stat") => self.stat(&words, handle),
            Some(&"cat") => self.cat(&words, handle),
            Some(&"ls") => self.ls(&words, handle),
            Some(&"ll") => self.ll(&words, handle),
            Some(&"touch") => self.touch(&words, handle),
            Some(&"mkdir") => self.mkdir(&words, handle),
            Some(&"rm") => self.rm(&words, handle),
            Some(&"mv") => self.mv(&words, handle),
            Some(&"cd") => self.cd(&words, handle),
            Some(&"help") => self.help(&words, handle),
            Some(&"kill") => self.kill(&words, handle),
            Some(&"sleep") => self.sleep(&words, handle),
            Some(&"ps") => self.ps(&words, handle),
            None => Ok(()),
            _ => Err("Unknown command".to_owned()),
        };
        if let Err(e) = result {
            println!("Error: {}", e);
        }

        while let Some((pid, result)) = handle
            .sc_wait_pid(WaitPidTarget::AnyChild, WaitPidOptions::NoHang)
            .expect("Wait for background tasks")
        {
            println!("[{}] finished: {:?}", pid, result);
        }
    }

    fn stat(&mut self, args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
        let path = args.get(1).ok_or("missing arg")?;
        let stat = sys.sc_stat(path)?;
        println!("{}", self._stat_line(stat));
        Ok(())
    }

    fn _stat_line(&mut self, stat: FileStat) -> String {
        let file_type = match stat.file_type {
            FileType::Regular => "file",
            FileType::Directory => "directory",
            FileType::CharacterDevice => "character device",
        }
        .to_owned();
        let permissions = match stat.permissions {
            FilePermissions::ReadOnly => "r-",
            FilePermissions::ReadWrite => "rw",
        }
        .to_owned();

        let size = format!("{} bytes", stat.size);
        format!(
            "{:>10} {:>4} {:>10} {:<13}",
            file_type,
            permissions,
            size,
            format!(
                "[{:?}:{}]",
                stat.inode_id.filesystem_id, stat.inode_id.number
            )
        )
    }

    fn cat(&mut self, args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
        let path = args.get(1).ok_or_else(|| "missing arg".to_owned())?;
        self._cat_file(path, sys)
    }

    fn _cat_file(&self, path: &str, sys: &mut ProcessHandle) -> Result<()> {
        let fd = sys.sc_open(path)?;
        let mut buf = vec![0; 1024];
        loop {
            //TODO if reading fails here, we leak the FD
            let n = sys.sc_read(fd, &mut buf)?;
            if n > 0 {
                let s = String::from_utf8_lossy(&buf[..n]);
                print!("{}", s);
            } else {
                break;
            }
        }
        sys.sc_close(fd)
    }

    fn ls(&mut self, args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
        let path: &str = args.get(1).unwrap_or(&".");
        let stat = sys.sc_stat(path)?;
        if stat.file_type == FileType::Regular {
            println!("{}", path);
        } else {
            let dir_fd = sys.sc_open(path).unwrap();
            let dir_entries = sys.sc_getdents(dir_fd)?;
            let names: Vec<String> = dir_entries.into_iter().map(|e| e.name).collect();
            println!("{}", names.join("\t\t"));
            sys.sc_close(dir_fd)?;
        }
        Ok(())
    }

    fn ll(&mut self, args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
        let path: &str = args.get(1).unwrap_or(&".");
        let stat = sys.sc_stat(path)?;
        if stat.file_type == FileType::Regular {
            println!("{}{:>10}", self._stat_line(stat), path);
        } else {
            let dir_fd = sys.sc_open(path)?;
            let dir_entries = sys.sc_getdents(dir_fd)?;
            for dir_entry in dir_entries {
                let child_name = dir_entry.name;
                let child_path = format!("{}/{}", path, child_name);
                let stat = sys.sc_stat(&child_path)?;
                println!("{:<44}{}", self._stat_line(stat), child_name);
            }
            sys.sc_close(dir_fd)?;
        }
        Ok(())
    }

    fn touch(&mut self, args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
        let path = args.get(1).ok_or_else(|| "missing arg".to_owned())?;
        sys.sc_create(*path, FileType::Regular, FilePermissions::ReadWrite)?;
        println!("File created");
        Ok(())
    }

    fn mkdir(&mut self, args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
        let path = args.get(1).ok_or_else(|| "missing arg".to_owned())?;
        sys.sc_create(*path, FileType::Directory, FilePermissions::ReadWrite)?;
        println!("Directory created");
        Ok(())
    }

    fn cd(&mut self, args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
        if let Some(&path) = args.get(1) {
            sys.sc_chdir(path)
        } else {
            sys.sc_chdir("/")
        }
    }

    fn rm(&mut self, args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
        let path = args.get(1).ok_or_else(|| "missing arg".to_owned())?;
        sys.sc_unlink(path)?;
        println!("File removed");
        Ok(())
    }

    fn mv(&mut self, args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
        if let (Some(&src_path), Some(&dst_path)) = (args.get(1), args.get(2)) {
            sys.sc_rename(src_path, dst_path)?;
            println!("File moved");
            Ok(())
        } else {
            Err("Error: missing arg(s)".to_owned())
        }
    }

    fn help(&mut self, _args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
        self._cat_file("/README", sys)
    }

    fn kill(&mut self, args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
        let pid = args.get(1).ok_or_else(|| "missing arg".to_owned())?;
        let pid = Pid::from_str(*pid).map_err(|_| "Not a valid pid".to_owned())?;
        sys.sc_kill(pid)
    }

    fn sleep(&mut self, args: &[&str], handle: &mut ProcessHandle) -> Result<()> {
        match args.get(1) {
            None => {
                let child_pid = handle.sc_spawn("/bin/sleep")?;
                let result =
                    handle.sc_wait_pid(WaitPidTarget::Pid(child_pid), WaitPidOptions::Default)?;
                assert_eq!(result, Some((child_pid, ProcessResult::ExitCode(0))));
            }
            Some(&"&") => {
                let child_pid = handle.sc_spawn("/bin/sleep")?;
                println!("[{}] running in background...", child_pid);
                self.background_processes.push(child_pid);
            }
            Some(arg) => {
                return Err(format!("Unknown arg: {}", arg));
            }
        }
        Ok(())
    }

    fn ps(&mut self, _args: &[&str], handle: &mut ProcessHandle) -> Result<()> {
        let fd = handle.sc_open("/proc/status")?;

        //TODO read arbitrarily large file
        let mut buf = vec![0; 2048];
        //TODO if reading fails, we leak the FD
        let n_read = handle.sc_read(fd, &mut buf)?;

        assert!(
            n_read < buf.len(),
            "Filled whole buffer when readingproc/status file: {:?}",
            String::from_utf8_lossy(&buf[..])
        );

        let content = String::from_utf8_lossy(&buf[..n_read]);
        let mut lines = content.lines();

        lines.next(); // uptime
        lines.next(); // number of processes
        println!(
            "{:>4}{:>8}  {:<10}{:>4}  NAME",
            "PID", "PARENT", "STATE", "FDs"
        );
        for line in lines {
            let words: Vec<&str> = line.split(' ').collect();
            println!(
                "{:>4}{:>8}  {:<10}{:>4}  {}",
                words[0], words[1], words[3], words[4], words[2]
            );
        }

        handle.sc_close(fd)?;

        Ok(())
    }
}
