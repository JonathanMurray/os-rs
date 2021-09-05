
#[derive(Debug, Clone, PartialEq)]
pub struct Path(String);

// A canonical absolute path
impl Path {
    pub fn resolve(mut self, relative_path: &str) -> Self {
        if relative_path == "." {
            return self;
        }
        if !self.0.ends_with('/') {
            self.0.push('/');
        }
        self.0.push_str(relative_path);
        self
    }

    pub fn parent(&self) -> Self {
        let (mut parent_path, _) = self
            .0
            .rsplit_once('/')
            .expect("canonical path must have parent");
        if parent_path.is_empty() {
            parent_path = "/";
        }
        Path(parent_path.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}


#[derive(PartialEq, Debug)]
pub enum FileType {
    Regular,
    Directory,
}


#[derive(PartialEq, Debug, Copy, Clone)]
pub enum FilePermissions {
    ReadWrite,
    ReadOnly,
}

#[derive(Debug)]
// Processes can be accessed from different threads.
struct Processes(HashMap<u32, Arc<Mutex<_Process>>>);
