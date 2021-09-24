use crate::sys::{ProcessHandle, ProcessResult, SpawnStdout, WaitPidOptions, WaitPidTarget};
use crate::util::{FilePermissions, FileStat, FileType, Pid};
use std::collections::HashSet;
use std::str::FromStr;

type Result<T> = core::result::Result<T, String>;

pub struct Shell {
    background_processes: HashSet<Pid>,
}

impl Shell {
    pub fn new() -> Self {
        Self {
            background_processes: Default::default(),
        }
    }

    pub fn handle(&mut self, handle: &mut ProcessHandle, input: String) {
        let words: Vec<&str> = input.split_whitespace().collect();
        if !words.is_empty() {
            if let Err(e) = self.handle_command(handle, words) {
                println!("Error: {}", e);
            }
        }
        self.check_finished_background_tasks(handle);
    }

    fn check_finished_background_tasks(&mut self, handle: &mut ProcessHandle) {
        while let Some((pid, result)) = handle
            .sc_wait_pid(WaitPidTarget::AnyChild, WaitPidOptions::NoHang)
            .expect("Wait for background tasks")
        {
            self.background_processes.remove(&pid);
            println!("[{}] finished: {:?}", pid.0, result);
        }
    }

    fn handle_command(&mut self, handle: &mut ProcessHandle, words: Vec<&str>) -> Result<()> {
        let command = words[0];
        match command {
            "stat" => self.stat(&words, handle),
            "cat" => self.cat(&words, handle),
            "ls" => self.ls(&words, handle),
            "ll" => self.ll(&words, handle),
            "touch" => self.touch(&words, handle),
            "mkdir" => self.mkdir(&words, handle),
            "rm" => self.rm(&words, handle),
            "mv" => self.mv(&words, handle),
            "cd" => self.cd(&words, handle),
            "help" => self.help(&words, handle),
            "kill" => self.kill(&words, handle),
            "sleep" => self.sleep(&words, handle),
            "ps" => self.ps(&words, handle),
            "jobs" => self.jobs(&words, handle),
            "pid" => self.pid(&words, handle),
            _ => Err("Unknown command".to_owned()),
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
            let n = match sys.sc_read(fd, &mut buf) {
                Ok(n) => n,
                Err(e) => {
                    if let Err(e) = sys.sc_close(fd) {
                        println!("WARN: Failed to close after failing to read: {}", e);
                    }
                    return Err(e);
                }
            };
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
        let pid = u32::from_str(*pid).map_err(|_| "Not a valid pid".to_owned())?;
        let pid = Pid(pid);
        sys.sc_kill(pid)
    }

    fn sleep(&mut self, args: &[&str], handle: &mut ProcessHandle) -> Result<()> {
        match args.get(1) {
            None => {
                let child_pid = handle.sc_spawn("/bin/sleep", SpawnStdout::Inherit)?;
                let result =
                    handle.sc_wait_pid(WaitPidTarget::Pid(child_pid), WaitPidOptions::Default)?;
                assert_eq!(result, Some((child_pid, ProcessResult::ExitCode(0))));
            }
            Some(&"&") => {
                let child_pid = handle.sc_spawn("/bin/sleep", SpawnStdout::Inherit)?;
                println!("[{}] running in background...", child_pid.0);
                self.background_processes.insert(child_pid);
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

    fn jobs(&mut self, _args: &[&str], handle: &mut ProcessHandle) -> Result<()> {
        self.check_finished_background_tasks(handle);

        if !self.background_processes.is_empty() {
            for pid in self.background_processes.iter() {
                println!("[{}] Running", pid.0);
            }
        }
        Ok(())
    }

    fn pid(&mut self, _args: &[&str], handle: &mut ProcessHandle) -> Result<()> {
        let pid = handle.sc_getpid();
        println!("{}", pid.0);
        Ok(())
    }
}
