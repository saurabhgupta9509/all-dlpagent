use std::sync::Mutex;
use once_cell::sync::Lazy;

static CONSOLE_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

pub struct ConsoleGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl ConsoleGuard {
    pub fn acquire() -> Self {
        Self {
            _lock: CONSOLE_LOCK.lock().unwrap(),
        }
    }
}

// Macro for synchronized output
#[macro_export]
macro_rules! sync_println {
    ($($arg:tt)*) => {
        {
            let _guard = $crate::utils::output_lock::ConsoleGuard::acquire();
            println!($($arg)*);
        }
    };
}

#[macro_export]
macro_rules! sync_print {
    ($($arg:tt)*) => {
        {
            let _guard = $crate::utils::output_lock::ConsoleGuard::acquire();
            print!($($arg)*);
        }
    };
}