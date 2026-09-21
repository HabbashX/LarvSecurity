//! Clipboard helpers with optional auto-clear.
//!
//! Secrets are copied via `arboard` and never logged. Auto-clear replaces
//! the clipboard contents after a timeout (best-effort; the OS clipboard
//! cannot be guaranteed empty in every environment).

use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ClipboardState {
    pub last_copied_label: Option<String>,
    pub auto_clear_secs: u64,
    pub auto_clear_enabled: bool,
    pending_clear: Arc<Mutex<Option<std::thread::JoinHandle<()>>>>,
}

impl Default for ClipboardState {
    fn default() -> Self {
        Self {
            last_copied_label: None,
            auto_clear_secs: 30,
            auto_clear_enabled: true,
            pending_clear: Arc::new(Mutex::new(None)),
        }
    }
}

impl ClipboardState {
    pub fn copy(&mut self, label: &str, text: &str) -> Result<(), String> {
        let mut cb = arboard::Clipboard::new().map_err(|e| e.to_string())?;
        cb.set_text(text.to_owned()).map_err(|e| e.to_string())?;
        self.last_copied_label = Some(label.to_string());
        if self.auto_clear_enabled {
            self.schedule_clear();
        }
        Ok(())
    }

    fn schedule_clear(&mut self) {
        let secs = self.auto_clear_secs;
        // Spawn a best-effort clearer; failures are silent by design.
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(secs));
            if let Ok(mut cb) = arboard::Clipboard::new() {
                let _ = cb.set_text(String::new());
            }
        });
        if let Ok(mut slot) = self.pending_clear.lock() {
            *slot = Some(handle);
        }
    }
}
