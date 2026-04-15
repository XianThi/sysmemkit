mod memory;
mod syscalls;
mod utils;
use crate::syscalls::invoker::SyscallInvoker;
use crate::syscalls::resolver::get_win32u_base;
use crate::utils::dbj2_hash;
pub use memory::buffer::{read, write};
pub use memory::process::{
    create_section, get_module_base, get_pid_by_hash, hijack_handle, map_view_of_section, openfile,
};
pub use memory::scanner::pattern_scan;
use std::ffi::c_void;
pub use syscalls::invoker::do_syscall;
pub use syscalls::resolver::{
    get_ntdll_base, get_ssn_by_hash, get_syscall_number, print_function_bytes,
};
use windows::Win32::UI::WindowsAndMessaging::GetDesktopWindow;

pub struct SysMemKit {
    process_handle: *mut std::ffi::c_void,
    ntdll_base: *mut c_void,
    invoker: SyscallInvoker,
}

impl SysMemKit {
    pub unsafe fn new(target_name: &str, hashed: bool) -> Option<Self> {
        let (ntdll_base, ntdll_size) = unsafe { get_ntdll_base() };
        if ntdll_base.is_null() {
            return None;
        }
        let invoker = unsafe {
            match SyscallInvoker::new(ntdll_base, ntdll_size) {
                Some(inv) => inv,
                None => {
                    return None;
                }
            }
        };

        /* win32u.dll test */
        // let (win32u_base, win32u_size) = unsafe { get_win32u_base() };
        // println!("win32u.dll {:X}", win32u_base as usize);
        // let handle =
        //     memory::process::openfile(invoker, ntdll_base, "C:\\windows\\system32\\win32u.dll")
        //         .unwrap();
        // println!("handle : {:?}", handle);
        // let createsection = memory::process::create_section(invoker, ntdll_base, handle).unwrap();
        // println!("create section : {:?}", createsection);
        // let mapviewsection =
        //     memory::process::map_view_of_section(invoker, ntdll_base, createsection).unwrap();
        // println!("mapview section : {:?}", mapviewsection);
        // let windowstation =
        //     get_ssn_by_hash(mapviewsection, dbj2_hash("NtUserGetProcessWindowStation")).unwrap();
        // println!("windowstation : {:?}", windowstation);
        // let userbuildhwndlist =
        //     get_ssn_by_hash(mapviewsection, dbj2_hash("NtUserBuildHwndList")).unwrap();
        // println!("userbuildhwndlist : {:?}", userbuildhwndlist);
        // let findwindowex =
        //     get_ssn_by_hash(mapviewsection, dbj2_hash("NtUserFindWindowEx")).unwrap();
        // println!("findwindowex : {:?}", findwindowex);
        // let discord =
        //     memory::process::find_window_syscall(invoker, findwindowex, "Arkadaşlar - Discord");
        // println!("discord : {:?}", discord);
        // memory::process::enum_windows_syscall(invoker, userbuildhwndlist);

        let mut hash: u32 = 0;
        if hashed == false {
            hash = utils::dbj2_hash(&target_name.to_lowercase());
        } else {
            hash = std::str::FromStr::from_str(target_name).unwrap();
        }
        unsafe {
            let pid = memory::process::get_pid_by_hash(&invoker, ntdll_base, hash)?;
            let handle = memory::process::hijack_handle(&invoker, ntdll_base, pid)?;
            Some(Self {
                process_handle: handle,
                ntdll_base,
                invoker,
            })
        }
    }

    pub unsafe fn read<T>(&self, address: usize) -> T {
        unsafe { memory::buffer::read(&self.invoker, self.ntdll_base, self.process_handle, address) }
    }

    pub unsafe fn write<T>(&self, address: usize, value: T) -> bool {
        unsafe {
            memory::buffer::write(
                &self.invoker,
                self.ntdll_base,
                self.process_handle,
                address,
                value,
            )
        }
    }

    pub unsafe fn scan(&self, pattern: &str, start: usize, size: usize) -> Option<usize> {
        unsafe { memory::scanner::pattern_scan(self.process_handle, start, size, pattern) }
    }

    pub unsafe fn getmodule(&self, module_name: &str) -> Option<usize> {
        let module_name_hash = utils::dbj2_hash(module_name);
        unsafe {
            memory::process::get_module_base(
                &self.invoker,
                self.ntdll_base,
                self.process_handle,
                module_name_hash,
            )
        }
    }
}
