// use serde::Serialize;
// use std::fs;
// use std::path::Path;

// #[derive(Serialize, Clone)]
// pub struct FSItem {
//     pub name: String,
//     pub fullPath: String,
//     pub isDirectory: bool,
//     pub size: u64,
// }

// #[derive(Serialize)]
// pub struct BrowseResponse {
//     pub agentId: u64,
//     pub currentPath: String,
//     pub parentPath: String,
//     pub items: Vec<FSItem>,

//     #[serde(default)]
//     pub partial: bool,

//     #[serde(default)]
//     pub complete: bool,

//     #[serde(default)]
//     pub chunkId: Option<u32>,
// }

// pub fn scan_directory(path: &str) -> Vec<FSItem> {
//     let mut items = Vec::new();
//     let p = Path::new(path);

//     if let Ok(read_dir) = fs::read_dir(p) {
//         for entry in read_dir.flatten() {
//             let file_name = entry.file_name().to_string_lossy().to_string();
//             let full_path = entry.path().to_string_lossy().to_string();
//             let metadata = entry.metadata().ok();

//             let is_dir = metadata
//                 .as_ref()
//                 .map(|m| m.is_dir())
//                 .unwrap_or(false);

//             let size = metadata
//                 .as_ref()
//                 .map(|m| m.len())
//                 .unwrap_or(0);

//             items.push(FSItem {
//                 name: file_name,
//                 fullPath: full_path,
//                 isDirectory: is_dir,
//                 size,
//             });
//         }
//     }

//     items
// }
