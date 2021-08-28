mod sys;

use std::io::{Cursor, Read};

use crate::sys::{FileType, System};

fn main() {
    let mut sys = System::new();

    let dir_id = sys.create("/", FileType::Directory);
    sys.create("/a", FileType::Regular);
    let subdir_id = sys.create("/subdir", FileType::Directory);
    sys.create("/subdir/a", FileType::Regular);
    let fd = sys.open("/a");
    sys.write(fd, &[1, 2, 3]);
    sys.seek(fd, 1);
    sys.write(fd, &[4, 5, 6]);
    sys.seek(fd, 2);
    let fd2 = sys.open("/a");
    let buf = &mut [0, 0, 0];
    sys.read(fd2, buf);
    println!("{:?}", buf);
    sys.close(fd);

    println!("Directory contents: {:?}", sys.list_dir("/"));
    println!("Subdirectory contents: {:?}", sys.list_dir("/subdir"));
}
