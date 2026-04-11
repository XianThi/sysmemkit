mod memory;
mod syscalls;
mod utils;
pub use memory::buffer::{read, write};
pub use memory::process::{get_module_base, get_pid_by_hash, hijack_handle};
pub use memory::scanner::pattern_scan;
use std::ffi::c_void;
pub use syscalls::invoker::do_syscall;
pub use syscalls::resolver::{
    get_ntdll_base, get_ssn_by_hash, get_syscall_number, print_function_bytes,
};

pub struct SysMemKit {
    process_handle: *mut std::ffi::c_void,
    base_address: usize,
}

impl SysMemKit {
    pub unsafe fn new(target_name: &str) -> Option<Self> {
        let hash = utils::dbj2_hash(&target_name.to_lowercase());
        unsafe {
            let pid = memory::process::get_pid_by_hash(hash)?;
            let handle = memory::process::hijack_handle(pid)?;

            Some(Self {
                process_handle: handle,
                base_address: 0,
            })
        }
    }

    pub unsafe fn read<T>(&self, address: usize) -> T {
        unsafe { memory::buffer::read(self.process_handle, address) }
    }

    pub unsafe fn write<T>(&self, address: usize, value: T) -> bool {
        unsafe { memory::buffer::write(self.process_handle, address, value) }
    }

    pub unsafe fn scan(&self, pattern: &str, start: usize, size: usize) -> Option<usize> {
        unsafe { memory::scanner::pattern_scan(self.process_handle, start, size, pattern) }
    }

    pub unsafe fn getmodule(&self, module_name: &str) -> Option<usize> {
        let module_name_hash = utils::dbj2_hash(module_name);
        unsafe { memory::process::get_module_base(self.process_handle, module_name_hash) }
    }
}
