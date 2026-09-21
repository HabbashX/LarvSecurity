//! Portable workspace persistence: appearance, favorites, recents,
//! JWT presets — never secrets. Stored as JSON next to the executable
//! (`LarvSecurity-config.json`), with export/import anywhere.

use serde::{Deserialize, Serialize};

use crate::models::ToolkitError;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JwtPreset {
    pub name: String,
    pub payload: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceData {
    pub version: u8,
    pub theme: String,
    pub accent: String,
    pub base_size: f32,
    pub mono_ui: bool,
    pub ui_scale: f32,
    pub corner: u8,
    pub motion: bool,
    pub language: String,
    pub clipboard_secs: u64,
    #[serde(default)]
    pub favorites: Vec<String>,
    #[serde(default)]
    pub recents: Vec<String>,
    #[serde(default)]
    pub jwt_presets: Vec<JwtPreset>,
}

impl Default for WorkspaceData {
    fn default() -> Self {
        Self {
            version: 1,
            theme: "Dark".into(),
            accent: "Indigo".into(),
            base_size: 13.5,
            mono_ui: false,
            ui_scale: 1.0,
            corner: 8,
            motion: true,
            language: "English".into(),
            clipboard_secs: 30,
            favorites: Vec::new(),
            recents: Vec::new(),
            jwt_presets: Vec::new(),
        }
    }
}

pub fn config_path() -> std::path::PathBuf {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()));
    exe_dir
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("LarvSecurity-config.json")
}

pub fn save_to(path: &std::path::Path, data: &WorkspaceData) -> Result<(), ToolkitError> {
    let json = serde_json::to_string_pretty(data)
        .map_err(|e| ToolkitError::FileWrite(e.to_string()))?;
    std::fs::write(path, json).map_err(|e| ToolkitError::FileWrite(e.to_string()))
}

pub fn load_from(path: &std::path::Path) -> Result<WorkspaceData, ToolkitError> {
    let raw = std::fs::read_to_string(path).map_err(|e| ToolkitError::FileRead(e.to_string()))?;
    let data: WorkspaceData =
        serde_json::from_str(&raw).map_err(|e| ToolkitError::FileRead(format!("bad workspace file: {e}")))?;
    if data.version != 1 {
        return Err(ToolkitError::FileRead("unsupported workspace version".into()));
    }
    Ok(data)
}
