use crate::sys::ProcessHandle;
use crate::util::{FilePermissions, FileStat, FileType};

type Result<T> = core::result::Result<T, String>;

pub fn handle(sys: &mut ProcessHandle, input: String) {
    let words: Vec<&str> = input.split_whitespace().collect();
    let result = match words.get(0) {
        Some(&"stat") => stat(&words, sys),
        Some(&"cat") => cat(&words, sys),
        Some(&"ls") => ls(&words, sys),
        Some(&"ll") => ll(&words, sys),
        Some(&"touch") => touch(&words, sys),
        Some(&"mkdir") => mkdir(&words, sys),
        Some(&"rm") => rm(&words, sys),
        Some(&"mv") => mv(&words, sys),
        Some(&"cd") => cd(&words, sys),
        Some(&"help") => help(&words, sys),
        None => Ok(()),
        _ => Err("Unknown command".to_owned()),
    };
    if let Err(e) = result {
        println!("Error: {}", e);
    }
}

fn stat(args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
    let path = args.get(1).ok_or("missing arg")?;
    let stat = sys.sc_stat(path)?;
    println!("{}", _stat_line(stat));
    Ok(())
}

fn _stat_line(stat: FileStat) -> String {
    let file_type = match stat.file_type {
        FileType::Regular => "file",
        FileType::Directory => "directory",
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

fn cat(args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
    let path = args.get(1).ok_or_else(|| "missing arg".to_owned())?;
    _cat_file(path, sys)
}

fn _cat_file(path: &str, sys: &mut ProcessHandle) -> Result<()> {
    let fd = sys.sc_open(path)?;
    let mut buf = vec![0; 1024];
    loop {
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

fn ls(args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
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

fn ll(args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
    let path: &str = args.get(1).unwrap_or(&".");
    let stat = sys.sc_stat(path)?;
    if stat.file_type == FileType::Regular {
        println!("{}{:>10}", _stat_line(stat), path);
    } else {
        let dir_fd = sys.sc_open(path)?;
        let dir_entries = sys.sc_getdents(dir_fd)?;
        for dir_entry in dir_entries {
            let child_name = dir_entry.name;
            let child_path = format!("{}/{}", path, child_name);
            let stat = sys.sc_stat(&child_path)?;
            println!("{:<44}{}", _stat_line(stat), child_name);
        }
        sys.sc_close(dir_fd)?;
    }
    Ok(())
}

fn touch(args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
    let path = args.get(1).ok_or_else(|| "missing arg".to_owned())?;
    sys.sc_create(*path, FileType::Regular, FilePermissions::ReadWrite)?;
    println!("File created");
    Ok(())
}

fn mkdir(args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
    let path = args.get(1).ok_or_else(|| "missing arg".to_owned())?;
    sys.sc_create(*path, FileType::Directory, FilePermissions::ReadWrite)?;
    println!("Directory created");
    Ok(())
}

fn cd(args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
    if let Some(&path) = args.get(1) {
        sys.sc_chdir(path)
    } else {
        sys.sc_chdir("/")
    }
}

fn rm(args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
    let path = args.get(1).ok_or_else(|| "missing arg".to_owned())?;
    sys.sc_remove(path)?;
    println!("File removed");
    Ok(())
}

fn mv(args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
    if let (Some(&src_path), Some(&dst_path)) = (args.get(1), args.get(2)) {
        sys.sc_rename(src_path, dst_path)?;
        println!("File moved");
        Ok(())
    } else {
        Err("Error: missing arg(s)".to_owned())
    }
}

fn help(_args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
    _cat_file("/README", sys)
}
