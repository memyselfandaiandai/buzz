use std::sync::{Mutex, OnceLock};

type Hook = Box<dyn Fn() + Send>;

fn cell() -> &'static Mutex<Option<Hook>> {
    static CELL: OnceLock<Mutex<Option<Hook>>> = OnceLock::new();
    CELL.get_or_init(|| Mutex::new(None))
}

/// Install (or clear, with `None`) the process-global test hook.
pub(crate) fn set(hook: Option<Hook>) {
    *cell().lock().unwrap_or_else(|e| e.into_inner()) = hook;
}

pub(crate) fn run() {
    if let Some(hook) = cell().lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
        hook();
    }
}
