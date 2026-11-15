use std::arch::asm;
use std::ffi::c_void;
use std::os::windows::raw::HANDLE;
use crate::include::def::{
    CLIENT_ID, DUPLICATE_SAME_ACCESS, OBJECT_ATTRIBUTES, OBJECT_ATTRIBUTES_OPENFILE,
    PROCESS_BASIC_INFORMATION, PROCESS_DUP_HANDLE, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    SYSTEM_EXTENDED_HANDLE_INFORMATION_CLASS, SYSTEM_HANDLE_INFORMATION_EX,
    SYSTEM_PROCESS_INFORMATION, SYSTEM_PROCESS_INFORMATION_CLASS, UNICODE_STRING,
};
use crate::syscalls::SyscallInvoker;
use crate::syscalls::resolver::get_ssn_by_hash;
use crate::utils::dbj2_hash;

#[cfg(feature = "discord")]
pub unsafe fn get_discord_overlay_pid(invoker: &dyn SyscallInvoker, ntdll: *mut c_void, discord_hash: u32) -> Option<u32> {
    unsafe {
        let nt_query_hash = dbj2_hash("NtQuerySystemInformation");
        let ssn_query = get_ssn_by_hash(ntdll, nt_query_hash)?;

        let mut buffer_size = 0x40000;
        let mut buffer =
            std::alloc::alloc(std::alloc::Layout::from_size_align(buffer_size, 16).unwrap());
        let mut ret_len: usize = 0;
        let mut args: [usize; 11] = [
            SYSTEM_PROCESS_INFORMATION_CLASS as usize,
            buffer as usize,
            buffer_size,
            &mut ret_len as *mut _ as usize,
            0,
            0, 0, 0, 0, 0, 0,
        ];

        let mut status = invoker.invoke(ssn_query, 0, &mut args);
        if status == 0xC0000004 {
            std::alloc::dealloc(
                buffer,
                std::alloc::Layout::from_size_align(buffer_size, 16).unwrap(),
            );
            buffer_size = ret_len + 0x1000;
            buffer =
                std::alloc::alloc(std::alloc::Layout::from_size_align(buffer_size, 16).unwrap());
            args[1] = buffer as usize;
            args[2] = buffer_size;
            status = invoker.invoke(ssn_query, 0, &mut args);
        }

        if status != 0 {
            std::alloc::dealloc(
                buffer,
                std::alloc::Layout::from_size_align(buffer_size, 16).unwrap(),
            );
            return None;
        }
        let mut current_ptr = buffer;
        let mut overlay_pid: Option<u32> = None;

        loop {
            let proc_info = current_ptr as *mut SYSTEM_PROCESS_INFORMATION;

            if !(*proc_info).image_name.buffer.is_null() {
                let name_len = (*proc_info).image_name.length as usize / 2;
                let name_slice =
                    std::slice::from_raw_parts((*proc_info).image_name.buffer, name_len);
                let name_string = String::from_utf16_lossy(name_slice);

                // Önce Discord.exe process'lerini bul
                if dbj2_hash(&name_string.to_lowercase()) == discord_hash {
                    let pid = (*proc_info).unique_process_id as u32;
                    println!("Discord process bulundu! PID: {}", pid);
                    // Bu process'in command line'ını oku
                    // SYSTEM_PROCESS_INFORMATION içinde command line direkt yok
                    // Onun için ayrıca process'i açıp command line'ı okumamız lazım
                    if let Some(cmdline) = get_process_command_line(invoker, ntdll, pid)
                        && cmdline.contains("--type=renderer") && cmdline.contains("discord") {
                            overlay_pid = Some(pid);
                            break;
                        }
                }
            }

            let next_offset = (*proc_info).next_entry_offset;
            if next_offset == 0 {
                break;
            }
            current_ptr = current_ptr.add(next_offset as usize);
        }

        // Fallback: Eğer renderer bulamazsak, en yüksek PID'li Discord'u dene
        if overlay_pid.is_none() {
            current_ptr = buffer;
            let mut highest_pid = 0;
            let mut last_discord_pid = 0;

            loop {
                let proc_info = current_ptr as *mut SYSTEM_PROCESS_INFORMATION;

                if !(*proc_info).image_name.buffer.is_null() {
                    let name_len = (*proc_info).image_name.length as usize / 2;
                    let name_slice =
                        std::slice::from_raw_parts((*proc_info).image_name.buffer, name_len);
                    let name_string = String::from_utf16_lossy(name_slice);

                    if dbj2_hash(&name_string.to_lowercase()) == discord_hash {
                        let pid = (*proc_info).unique_process_id as u32;
                        last_discord_pid = pid;
                        if pid > highest_pid {
                            highest_pid = pid;
                        }
                    }
                }

                let next_offset = (*proc_info).next_entry_offset;
                if next_offset == 0 {
                    break;
                }
                current_ptr = current_ptr.add(next_offset as usize);
            }

            // En yüksek PID genelde renderer process olur
            if highest_pid > 0 {
                overlay_pid = Some(highest_pid);
            } else if last_discord_pid > 0 {
                overlay_pid = Some(last_discord_pid);
            }
        }

        std::alloc::dealloc(
            buffer,
            std::alloc::Layout::from_size_align(buffer_size, 16).unwrap(),
        );

        overlay_pid
    }
}

#[cfg(feature = "discord")]
fn get_process_command_line(
    invoker: &dyn SyscallInvoker,
    ntdll: *mut c_void,
    pid: u32,
) -> Option<String> {
    unsafe {
        let handle = hijack_handle(invoker, ntdll, pid);
        if let Some(process_handle) = handle {
            let ssn_query = get_ssn_by_hash(ntdll, dbj2_hash("NtQueryInformationProcess"))?;
            let ssn_read = get_ssn_by_hash(ntdll, dbj2_hash("NtReadVirtualMemory"))?;

            let mut pbi = PROCESS_BASIC_INFORMATION::default();
            let mut ret_len = 0u32;

            let mut args_query: [usize; 11] = [
                process_handle as usize,
                0,
                &mut pbi as *mut _ as usize,
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as usize,
                &mut ret_len as *mut _ as usize,
                0, 0, 0, 0, 0, 0,
            ];

            let status = invoker.invoke(ssn_query, 0, &mut args_query);
            if status != 0 {
                return None;
            }

            let peb_addr = pbi.peb_base_address as usize;
            if peb_addr == 0 {
                return None;
            }

            // PEB içindeki ProcessParameters yapısının adresini oku
            let mut process_parameters_addr: usize = 0;
            if !read_remote(
                invoker,
                process_handle,
                ssn_read,
                peb_addr + 0x20, // ProcessParameters offset'u genelde 0x20'dir
                &mut process_parameters_addr,
            ) || process_parameters_addr == 0
            {
                return None;
            }

            // ProcessParameters içindeki CommandLine UNICODE_STRING'ini oku
            let mut command_line_unicode = UNICODE_STRING {
                length: 0,
                maximum_length: 0,
                buffer: std::ptr::null_mut(),
            };
            if !read_remote(
                invoker,
                process_handle,
                ssn_read,
                process_parameters_addr + 0x70, // CommandLine offset'u genelde 0x70'dir
                &mut command_line_unicode,
            ) || command_line_unicode.buffer.is_null()
                || command_line_unicode.length == 0
            {
                return None;
            }

            // CommandLine string'ini oku
            let name_len = (command_line_unicode.length / 2) as usize;
            let mut name_buf = vec![0u16; name_len];
            if !read_remote_buffer(
                invoker,
                process_handle,
                ssn_read,
                command_line_unicode.buffer as usize,
                name_buf.as_mut_ptr() as usize,
                name_len * 2,
            ) {
                return None;
            }
            let command_line = String::from_utf16_lossy(&name_buf);
            return Some(command_line);
        }
        None
    }
}

/// Süreç adı hash'inden PID bulur (`NtQuerySystemInformation`).
///
/// # Safety
///
/// `invoker` geçerli bir `SyscallInvoker` (ntdll stub'ları çözülmüş) olmalıdır; `ntdll` gerçek
/// ntdll image tabanını göstermelidir.
pub unsafe fn get_pid_by_hash(
    invoker: &dyn SyscallInvoker,
    ntdll: *mut c_void,
    target_name_hash: u32,
) -> Option<u32> {
    unsafe {
        let nt_query_hash = dbj2_hash("NtQuerySystemInformation");

        let ssn_query = get_ssn_by_hash(ntdll, nt_query_hash)?;
        // print!(
        //     "{} nt_query_hash için syscall numarası bulundu! SSN: {}.\r\n",
        //     nt_query_hash, ssn_query
        // );
        let mut buffer_size = 0x40000;
        // Tek bir Layout saklanır; alloc/dealloc her zaman aynı layout ile yapılır.
        let mut layout = match std::alloc::Layout::from_size_align(buffer_size, 16) {
            Ok(l) => l,
            Err(_) => return None,
        };
        let mut buffer = std::alloc::alloc(layout);
        if buffer.is_null() {
            return None;
        }
        let mut ret_len: usize = 0;
        let mut args: [usize; 11] = [
            SYSTEM_PROCESS_INFORMATION_CLASS as usize,
            buffer as usize,
            buffer_size,
            &mut ret_len as *mut _ as usize,
            0,
            0, 0, 0, 0, 0, 0,
        ];

        let mut status = invoker.invoke(ssn_query, 0, &mut args);
        if status == 0xC0000004 {
            std::alloc::dealloc(buffer, layout);
            buffer_size = ret_len + 0x1000;
            layout = match std::alloc::Layout::from_size_align(buffer_size, 16) {
                Ok(l) => l,
                Err(_) => return None,
            };
            buffer = std::alloc::alloc(layout);
            if buffer.is_null() {
                return None;
            }

            args[1] = buffer as usize;
            args[2] = buffer_size;
            status = invoker.invoke(ssn_query, 0, &mut args);
        }
        if status != 0 {
            std::alloc::dealloc(buffer, layout);
            return None;
        }

        let mut current_ptr = buffer;
        loop {
            let proc_info = current_ptr as *mut SYSTEM_PROCESS_INFORMATION;

            if !(*proc_info).image_name.buffer.is_null() {
                let name_len = (*proc_info).image_name.length as usize / 2;
                let name_slice =
                    std::slice::from_raw_parts((*proc_info).image_name.buffer, name_len);

                let name_string = String::from_utf16_lossy(name_slice);
                if dbj2_hash(&name_string.to_lowercase()) == target_name_hash {
                    let pid = (*proc_info).unique_process_id as u32;
                    std::alloc::dealloc(buffer, layout);
                    return Some(pid);
                }
            }

            let next_offset = (*proc_info).next_entry_offset;
            if next_offset == 0 {
                break;
            }
            current_ptr = current_ptr.add(next_offset as usize);
        }

        std::alloc::dealloc(buffer, layout);
        None
    }
}

pub unsafe fn manual_open_process(
    invoker: &dyn SyscallInvoker,
    ntdll: *mut c_void,
    pid: u32,
) -> Option<*mut c_void> {
    unsafe {
        if ntdll.is_null() {
            return None;
        }

        let nt_open_hash = dbj2_hash("NtOpenProcess");
        let ssn_open = match get_ssn_by_hash(ntdll, nt_open_hash) {
            Some(ssn) => ssn,
            None => {
                return None;
            }
        };

        let mut handle: *mut c_void = std::ptr::null_mut();

        let mut obj_attr = OBJECT_ATTRIBUTES {
            length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            root_directory: std::ptr::null_mut(),
            object_name: std::ptr::null_mut(),
            attributes: 0,
            security_descriptor: std::ptr::null_mut(),
            security_quality_of_service: std::ptr::null_mut(),
        };

        let mut client_id = CLIENT_ID {
            unique_process: pid as *mut c_void,
            unique_thread: std::ptr::null_mut(),
        };

        let access_mask =
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_VM_WRITE;

        let mut args: [usize; 11] = [
            &mut handle as *mut _ as usize,
            access_mask as usize,
            &mut obj_attr as *mut _ as usize,
            &mut client_id as *mut _ as usize,
            0, 0, 0, 0, 0, 0, 0,
        ];

        let status = invoker.invoke(ssn_open, 0, &mut args);

        if status == 0 && !handle.is_null() {
            let ssn_query = match get_ssn_by_hash(ntdll, dbj2_hash("NtQueryInformationProcess")) {
                Some(ssn) => ssn,
                None => {
                    let mut close_args: [usize; 11] = [handle as usize, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
                    if let Some(ssn_close) = get_ssn_by_hash(ntdll, dbj2_hash("NtClose")) {
                        invoker.invoke(ssn_close, 0, &mut close_args);
                    }
                    return None;
                }
            };
            let mut pbi = PROCESS_BASIC_INFORMATION::default();
            let mut ret_len = 0u32;

            let mut test_args: [usize; 11] = [
                handle as usize,
                0,
                &mut pbi as *mut _ as usize,
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as usize,
                &mut ret_len as *mut _ as usize,
                0, 0, 0, 0, 0, 0,
            ];

            let test_status = invoker.invoke(ssn_query, 0, &mut test_args);
            if test_status == 0 {
                return Some(handle);
            } else {
                let nt_close_hash = dbj2_hash("NtClose");
                let ssn_close = get_ssn_by_hash(ntdll, nt_close_hash)?;
                let mut close_args: [usize; 11] = [handle as usize, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
                invoker.invoke(ssn_close, 0, &mut close_args);
                return None;
            }
        }

        None
    }
}

/// Hedef PID için açık bir process handle'ını sistem genelinde arayıp (`SystemExtendedHandleInformation=0x40`)
/// `NtDuplicateObject` ile mevcut sürece kopyalar (Handle Hijacking - Faz 4).
///
/// # Yetki Gereksinimleri
/// - Diğer kullanıcıların veya SYSTEM oturumundaki süreçlerin (örn. `lsass.exe`, `csrss.exe`)
///   handle'larını duplicate edebilmek için çağıran sürecin `SeDebugPrivilege` ayrıcalığına sahip olması gerekir.
/// - Aynı kullanıcı oturumundaki süreçlerin handle'ları ek bir yetki gerekmeksizin çoğaltılabilir.
///
/// # Geri Dönüş ve Fallback
/// - Sistem handle tablosunda hedef PID'ye işaret eden uygun bir handle bulunursa `Some(handle)` döner.
/// - Hiçbir süreçte açık handle bulunamazsa veya yetki yetersizse, `manual_open_process` (`NtOpenProcess`)
///   yoluna güvenli şekilde düşer (fallback).
///
/// # Safety
///
/// `target_pid` canlı bir süreç olmalı ve `ntdll` geçerli image tabanını göstermelidir.
pub unsafe fn hijack_handle(
    invoker: &dyn SyscallInvoker,
    ntdll: *mut c_void,
    target_pid: u32,
) -> Option<*mut c_void> {
    if ntdll.is_null() {
        return None;
    }

    // 1. Gerekli syscall SSN'lerini çöz
    let ssn_query_sys = get_ssn_by_hash(ntdll, dbj2_hash("NtQuerySystemInformation"));
    let ssn_dup = get_ssn_by_hash(ntdll, dbj2_hash("NtDuplicateObject"));
    let ssn_open = get_ssn_by_hash(ntdll, dbj2_hash("NtOpenProcess"));
    let ssn_query_proc = get_ssn_by_hash(ntdll, dbj2_hash("NtQueryInformationProcess"));
    let ssn_close = get_ssn_by_hash(ntdll, dbj2_hash("NtClose"));

    if let (Some(ssn_query_sys), Some(ssn_dup), Some(ssn_open), Some(ssn_query_proc), Some(ssn_close)) =
        (ssn_query_sys, ssn_dup, ssn_open, ssn_query_proc, ssn_close)
    {
        let mut buffer_size: usize = 0x100000;
        let layout = std::alloc::Layout::from_size_align(buffer_size, 16).ok()?;
        let mut buffer = std::alloc::alloc(layout);
        if buffer.is_null() {
            return unsafe { manual_open_process(invoker, ntdll, target_pid) };
        }

        let mut ret_len: usize = 0;
        let mut args: [usize; 11] = [
            SYSTEM_EXTENDED_HANDLE_INFORMATION_CLASS as usize,
            buffer as usize,
            buffer_size,
            &mut ret_len as *mut _ as usize,
            0, 0, 0, 0, 0, 0, 0,
        ];

        let mut status = invoker.invoke(ssn_query_sys, 0, &mut args);
        while status == 0xC0000004 && buffer_size < 0x8000000 {
            std::alloc::dealloc(buffer, layout);
            buffer_size = if ret_len > buffer_size {
                ret_len + 0x20000
            } else {
                buffer_size * 2
            };
            if let Ok(new_layout) = std::alloc::Layout::from_size_align(buffer_size, 16) {
                buffer = std::alloc::alloc(new_layout);
                if buffer.is_null() {
                    return unsafe { manual_open_process(invoker, ntdll, target_pid) };
                }
                args[1] = buffer as usize;
                args[2] = buffer_size;
                status = invoker.invoke(ssn_query_sys, 0, &mut args);
            } else {
                break;
            }
        }

        if status == 0 && !buffer.is_null() {
            let info = &*(buffer as *const SYSTEM_HANDLE_INFORMATION_EX);
            let handle_count = info.number_of_handles;
            let entries = std::slice::from_raw_parts(info.handles.as_ptr(), handle_count);

            let my_pid = {
                let mut pid: usize = 0;
                #[cfg(target_arch = "x86_64")]
                asm!("mov {}, gs:[0x40]", out(reg) pid, options(nostack, readonly));
                pid
            };

            for entry in entries {
                let owner_pid = entry.unique_process_id;
                if owner_pid == my_pid || owner_pid <= 4 {
                    continue;
                }

                let access = entry.granted_access;
                // Bellek okuma yetkisi (PROCESS_VM_READ: 0x0010) zorunludur; sadece sorgu yetkisi olan handle'lar elenir.
                if (access & PROCESS_VM_READ) == 0 {
                    continue;
                }

                let mut owner_handle: *mut c_void = std::ptr::null_mut();
                let mut obj_attr = OBJECT_ATTRIBUTES {
                    length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
                    root_directory: std::ptr::null_mut(),
                    object_name: std::ptr::null_mut(),
                    attributes: 0,
                    security_descriptor: std::ptr::null_mut(),
                    security_quality_of_service: std::ptr::null_mut(),
                };
                let mut client_id = CLIENT_ID {
                    unique_process: owner_pid as *mut c_void,
                    unique_thread: std::ptr::null_mut(),
                };
                let mut open_args: [usize; 11] = [
                    &mut owner_handle as *mut _ as usize,
                    PROCESS_DUP_HANDLE as usize,
                    &mut obj_attr as *mut _ as usize,
                    &mut client_id as *mut _ as usize,
                    0, 0, 0, 0, 0, 0, 0,
                ];

                if invoker.invoke(ssn_open, 0, &mut open_args) == 0 && !owner_handle.is_null() {
                    let mut dup_handle: *mut c_void = std::ptr::null_mut();
                    let current_process = !0usize;
                    let mut dup_args: [usize; 11] = [
                        owner_handle as usize,
                        entry.handle_value,
                        current_process,
                        &mut dup_handle as *mut _ as usize,
                        0,
                        0,
                        DUPLICATE_SAME_ACCESS as usize,
                        0, 0, 0, 0,
                    ];

                    let dup_status = invoker.invoke(ssn_dup, 0, &mut dup_args);

                    let mut close_args: [usize; 11] = [owner_handle as usize, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
                    invoker.invoke(ssn_close, 0, &mut close_args);

                    if dup_status == 0 && !dup_handle.is_null() {
                        let mut pbi = PROCESS_BASIC_INFORMATION::default();
                        let mut ret_query_len = 0u32;
                        let mut query_args: [usize; 11] = [
                            dup_handle as usize,
                            0,
                            &mut pbi as *mut _ as usize,
                            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as usize,
                            &mut ret_query_len as *mut _ as usize,
                            0, 0, 0, 0, 0, 0,
                        ];

                        if invoker.invoke(ssn_query_proc, 0, &mut query_args) == 0 && pbi.unique_pid == target_pid as usize {
                            if let Ok(cur_layout) = std::alloc::Layout::from_size_align(buffer_size, 16) {
                                std::alloc::dealloc(buffer, cur_layout);
                            }
                            return Some(dup_handle);
                        }

                        let mut close_dup_args: [usize; 11] = [dup_handle as usize, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
                        invoker.invoke(ssn_close, 0, &mut close_dup_args);
                    }
                }
            }

            if let Ok(cur_layout) = std::alloc::Layout::from_size_align(buffer_size, 16) {
                std::alloc::dealloc(buffer, cur_layout);
            }
        }
    }

    unsafe { manual_open_process(invoker, ntdll, target_pid) }
}

/// Dosyayı `NtOpenFile` ile açar; bölüm (section) eşleme için handle döner.
///
/// # Safety
///
/// `invoker` başlatılmış olmalı; `file_path` yerel dosya sisteminde var olan bir yol olmalıdır.
/// Handle çağırana aittir ve `NtClose` ile kapatılmalıdır.
pub unsafe fn openfile(
    invoker: &dyn SyscallInvoker,
    ntdll: *mut c_void,
    path: &str,
) -> Option<std::os::windows::raw::HANDLE> {
    let full_path = format!(r"\??\{}", path);
    let mut utf16_path: Vec<u16> = full_path.encode_utf16().chain(std::iter::once(0)).collect();

    let mut unicode_string = UNICODE_STRING {
        length: ((utf16_path.len() - 1) * 2) as u16,
        maximum_length: (utf16_path.len() * 2) as u16,
        buffer: utf16_path.as_mut_ptr(),
    };
    let mut obj_attr = OBJECT_ATTRIBUTES_OPENFILE {
        length: std::mem::size_of::<OBJECT_ATTRIBUTES_OPENFILE>() as u32,
        root_directory: std::ptr::null_mut(),
        object_name: &mut unicode_string,
        attributes: 0x00000040, // OBJ_CASE_INSENSITIVE
        security_descriptor: std::ptr::null_mut(),
        security_quality_of_service: std::ptr::null_mut(),
    };

    let mut file_handle: std::os::windows::raw::HANDLE = std::ptr::null_mut();
    let mut io_status = [0usize; 2]; // IO_STATUS_BLOCK
    let mut args: [usize; 11] = [
        &mut file_handle as *mut _ as usize, // FileHandle
        0x100021_usize,                   // DesiredAccess
        &mut obj_attr as *mut _ as usize,    //  ObjectAttributes
        io_status.as_mut_ptr() as usize,     // IoStatusBlock
        1_usize,                          // ShareAccess (FILE_SHARE_READ)
        0x00000020_usize,                 // OpenOptions (FILE_NON_DIRECTORY_FILE)
        0, 0, 0, 0, 0,
    ];

    let ssn = get_ssn_by_hash(ntdll, dbj2_hash("NtOpenFile"))?;
    let status = invoker.invoke(ssn, 0, &mut args);

    if status == 0 {
        Some(file_handle)
    } else {
        println!("Hata Kodu (NTSTATUS): 0x{:X}", status);
        None
    }
}

/// Dosya handle'ından `SEC_IMAGE` bölümü oluşturur.
///
/// # Safety
///
/// `file_handle`, `openfile` ile alınmış ve okuma yetkisi olan geçerli bir handle olmalıdır.
/// Dönen section handle'ı çağıran kapatmalıdır.
pub unsafe fn create_section(
    invoker: &dyn SyscallInvoker,
    ntdll: *mut c_void,
    file_handle: HANDLE,
) -> Option<HANDLE> {
    let mut section_handle: HANDLE = std::ptr::null_mut();
    let mut args: [usize; 11] = [
        &mut section_handle as *mut _ as usize, // 1. SectionHandle (Out)
        0xF001F_usize,                       // 2. DesiredAccess (SECTION_ALL_ACCESS)
        0_usize,                             // 3. ObjectAttributes (Null)
        0_usize,                             // 4. MaximumSize (Null)
        0x02_usize,                          // 5. SectionPageProtection (PAGE_READONLY)
        0x01000000_usize,                    // 6. AllocationAttributes (SEC_IMAGE)
        file_handle as usize,                   // 7. FileHandle
        0, 0, 0, 0,
    ];

    let ssn = get_ssn_by_hash(ntdll, dbj2_hash("NtCreateSection"))?;
    let status = invoker.invoke(ssn, 0, &mut args);

    if status == 0 {
        Some(section_handle)
    } else {
        println!("NtCreateSection Hatası: 0x{:X}", status);
        None
    }
}

/// Bölümü adres uzayına eşler (module base döner).
///
/// # Safety
///
/// `section_handle` geçerli bir section handle'ı olmalıdır; eşlenen görünüm süreç ömrü boyunca
/// geçerli kalır ve `NtUnmapViewOfSection` ile kaldırılmalıdır.
pub unsafe fn map_view_of_section(
    invoker: &dyn SyscallInvoker,
    ntdll: *mut c_void,
    section_handle: HANDLE,
) -> Option<*mut c_void> {
    let mut base_address: *mut c_void = std::ptr::null_mut();
    let mut view_size: usize = 0;
    let mut args: [usize; 11] = [
        section_handle as usize,              // 1. SectionHandle
        -1isize as usize,                     // 2. ProcessHandle (NtCurrentProcess)
        &mut base_address as *mut _ as usize, // 3. BaseAddress
        0_usize,                           // 4. ZeroBits
        0_usize,                           // 5. CommitSize
        0_usize,                           // 6. SectionOffset
        &mut view_size as *mut _ as usize,    // 7. ViewSize
        1_usize,                           // 8. InheritDisposition
        0_usize,                           // 9. AllocationType
        0x02_usize,                        // 10. Win32Protect (PAGE_READONLY)
        0_usize,
    ];

    let ssn = get_ssn_by_hash(ntdll, dbj2_hash("NtMapViewOfSection"))?;
    let status = invoker.invoke(ssn, 0, &mut args);

    if status == 0 {
        println!("dosya başarıyla haritalandı! Adres: {:?}", base_address);
        Some(base_address)
    } else {
        println!("NtMapViewOfSection Hatası: 0x{:X}", status);
        None
    }
}

// Faz 1'de feature flag arkasına alınacak (Discord/win32u deneyleri).
#[allow(dead_code)]
#[cfg(feature = "discord")]
pub unsafe fn find_window_syscall(invoker: &dyn SyscallInvoker, ssn: u16, title: &str) -> isize {
    let utf16_title: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
    let mut unicode_title = UNICODE_STRING {
        length: ((utf16_title.len() - 1) * 2) as u16,
        maximum_length: (utf16_title.len() * 2) as u16,
        buffer: utf16_title.as_ptr() as *mut u16,
    };

    let mut args: [usize; 11] = [
        0_usize,                            // 1. hwndParent
        0_usize,                            // 2. hwndChildAfter
        0_usize,                            // 3. className
        &mut unicode_title as *mut _ as usize, // 4. windowName
        0_usize,                            // 5. dwType
        0, 0, 0, 0, 0, 0,
    ];
    let handle = unsafe { invoker.invoke(ssn, 0, &mut args) };
    handle as isize
}

// Faz 1'de feature flag arkasına alınacak (Discord/win32u deneyleri).
#[allow(dead_code)]
#[cfg(feature = "discord")]
pub unsafe fn enum_windows_syscall(invoker: &dyn SyscallInvoker, ssn: u16) {
    let mut count: u32 = 0;
    let mut hwnd_buffer = [0isize; 1024];

    let mut args: [usize; 11] = [
        0_usize,                        // 1. hDesktop
        0_usize,                        // 2. hwndParent
        1_usize,                        // 3. bChildren
        0_usize,                        // 4. dwThreadId
        0_usize,                        // 5. lParam
        hwnd_buffer.as_mut_ptr() as usize, // 6. pWndList
        &mut count as *mut _ as usize,     // 7. pCount
        0, 0, 0, 0,
    ];

    let status = invoker.invoke(ssn, 0, &mut args);
    println!("staus: {:X}", status);
    if status == 0 {
        println!("Toplam {} pencere bulundu!", count);
        for (i, hwnd) in hwnd_buffer.iter().take(count as usize).enumerate() {
            println!("HWND [{}]: 0x{:X}", i, hwnd);
        }
    }
}

unsafe fn read_remote<T>(
    invoker: &dyn SyscallInvoker,
    handle: *mut c_void,
    ssn: u16,
    addr: usize,
    out: *mut T,
) -> bool {
    let mut bytes_read = 0usize;
    let size = std::mem::size_of::<T>();
    let mut args: [usize; 11] = [
        handle as usize,
        addr,
        out as usize,
        size,
        &mut bytes_read as *mut usize as usize,
        0, 0, 0, 0, 0, 0,
    ];
    let status = unsafe { invoker.invoke(ssn, 0, &mut args) };
    status == 0 && bytes_read == size
}

unsafe fn read_remote_buffer(
    invoker: &dyn SyscallInvoker,
    handle: *mut c_void,
    ssn: u16,
    addr: usize,
    out: usize,
    size: usize,
) -> bool {
    let mut bytes_read = 0usize;
    let mut args: [usize; 11] = [
        handle as usize,
        addr,
        out,
        size,
        &mut bytes_read as *mut usize as usize,
        0, 0, 0, 0, 0, 0,
    ];
    let status = unsafe { invoker.invoke(ssn, 0, &mut args) };
    status == 0 && bytes_read == size
}

/// Uzak sürecin PEB/Ldr listesinden modül taban adresini bulur.
///
/// # Safety
///
/// `process_handle` hedef süreçte `PROCESS_QUERY_INFORMATION`/`VM_READ` yetkileriyle açılmış
/// olmalıdır; aksi halde `None` döner.
/// Uzak sürecin PEB/Ldr listesinden modül taban adresini (Image Base) bulur.
///
/// x64 sabit PEB offsetleri (`PEB.Ldr: 0x18`, `InLoadOrder: 0x10`, `DllBase: 0x30`, `BaseDllName: 0x58`)
/// ve `MZ`/`PE` başlık doğrulaması kullanır; x86 ayrımı `cfg(target_arch)` ile yapılır.
///
/// # Safety
///
/// `process_handle` hedef süreçte `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` yetkileriyle açılmış
/// olmalıdır; aksi halde `None` döner.
pub unsafe fn get_module_base(
    invoker: &dyn SyscallInvoker,
    ntdll: *mut c_void,
    process_handle: *mut c_void,
    module_name_hash: u32,
) -> Option<usize> {
    if process_handle.is_null() || process_handle == -1isize as *mut c_void || ntdll.is_null() {
        return None;
    }

    let ssn_query = get_ssn_by_hash(ntdll, dbj2_hash("NtQueryInformationProcess"))?;
    let ssn_read = get_ssn_by_hash(ntdll, dbj2_hash("NtReadVirtualMemory"))?;

    let mut pbi = PROCESS_BASIC_INFORMATION::default();
    let mut ret_len = 0u32;

    let mut args_query: [usize; 11] = [
        process_handle as usize,
        0,
        &mut pbi as *mut _ as usize,
        std::mem::size_of::<PROCESS_BASIC_INFORMATION>(),
        &mut ret_len as *mut _ as usize,
        0, 0, 0, 0, 0, 0,
    ];

    let status = invoker.invoke(ssn_query, 0, &mut args_query);
    if status != 0 {
        return None;
    }

    let peb_addr = pbi.peb_base_address as usize;
    if peb_addr == 0 {
        return None;
    }

    #[cfg(target_arch = "x86_64")]
    {
        // x64 sabit PEB offseti: PEB.Ldr = 0x18
        let mut ldr_ptr: usize = 0;
        if !read_remote(invoker, process_handle, ssn_read, peb_addr + 0x18, &mut ldr_ptr)
            || ldr_ptr == 0
        {
            return None;
        }

        // PEB_LDR_DATA.InLoadOrderModuleList = 0x10 (LIST_ENTRY: Flink, Blink)
        let head_flink = ldr_ptr + 0x10;
        let mut current_entry: usize = 0;
        if !read_remote(invoker, process_handle, ssn_read, head_flink, &mut current_entry)
            || current_entry == 0
        {
            return None;
        }

        let mut iteration = 0;
        while current_entry != 0 && current_entry != head_flink {
            iteration += 1;
            if iteration > 500 {
                break;
            }

            // LDR_DATA_TABLE_ENTRY (InLoadOrder):
            // DllBase: offset 0x30
            // BaseDllName: offset 0x58
            let mut dll_base: usize = 0;
            if read_remote(invoker, process_handle, ssn_read, current_entry + 0x30, &mut dll_base)
                && dll_base != 0
            {
                // MZ ve PE başlık doğrulaması
                if is_valid_pe(invoker, process_handle, ssn_read, dll_base) {
                    let mut name_unicode = UNICODE_STRING {
                        length: 0,
                        maximum_length: 0,
                        buffer: std::ptr::null_mut(),
                    };

                    if read_remote(
                        invoker,
                        process_handle,
                        ssn_read,
                        current_entry + 0x58,
                        &mut name_unicode,
                    ) && !name_unicode.buffer.is_null()
                        && name_unicode.length > 0
                    {
                        let name_len = (name_unicode.length / 2) as usize;
                        let mut name_buf = vec![0u16; name_len];
                        if read_remote_buffer(
                            invoker,
                            process_handle,
                            ssn_read,
                            name_unicode.buffer as usize,
                            name_buf.as_mut_ptr() as usize,
                            name_len * 2,
                        ) {
                            let name = String::from_utf16_lossy(&name_buf).to_lowercase();
                            if dbj2_hash(&name) == module_name_hash {
                                return Some(dll_base);
                            }
                        }
                    }
                }
            }

            // Sonraki LDR_DATA_TABLE_ENTRY (Flink offset 0x00)
            if !read_remote(invoker, process_handle, ssn_read, current_entry, &mut current_entry) {
                break;
            }
        }

        None
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        // 32-bit x86 yolu (cfg(not(target_arch = "x86_64")))
        // PEB.Ldr offset: 0x0C
        let mut ldr_ptr: u32 = 0;
        if !read_remote(invoker, process_handle, ssn_read, peb_addr + 0x0C, &mut ldr_ptr)
            || ldr_ptr == 0
        {
            return None;
        }

        let head_flink = (ldr_ptr + 0x0C) as usize;
        let mut current_entry: u32 = 0;
        if !read_remote(invoker, process_handle, ssn_read, head_flink, &mut current_entry)
            || current_entry == 0
        {
            return None;
        }

        let mut iteration = 0;
        while current_entry != 0 && current_entry as usize != head_flink {
            iteration += 1;
            if iteration > 500 {
                break;
            }

            let entry_usize = current_entry as usize;
            let mut dll_base: u32 = 0;
            if read_remote(invoker, process_handle, ssn_read, entry_usize + 0x18, &mut dll_base)
                && dll_base != 0
            {
                if is_valid_pe(invoker, process_handle, ssn_read, dll_base as usize) {
                    let mut name_buf_ptr: u32 = 0;
                    let mut name_len: u16 = 0;
                    let _ = read_remote(invoker, process_handle, ssn_read, entry_usize + 0x2C, &mut name_len);
                    let _ = read_remote(invoker, process_handle, ssn_read, entry_usize + 0x30, &mut name_buf_ptr);

                    if name_buf_ptr != 0 && name_len > 0 {
                        let chars = (name_len / 2) as usize;
                        let mut name_buf = vec![0u16; chars];
                        if read_remote_buffer(
                            invoker,
                            process_handle,
                            ssn_read,
                            name_buf_ptr as usize,
                            name_buf.as_mut_ptr() as usize,
                            chars * 2,
                        ) {
                            let name = String::from_utf16_lossy(&name_buf).to_lowercase();
                            if dbj2_hash(&name) == module_name_hash {
                                return Some(dll_base as usize);
                            }
                        }
                    }
                }
            }

            if !read_remote(invoker, process_handle, ssn_read, entry_usize, &mut current_entry) {
                break;
            }
        }

        None
    }
}

/// Hedef süreçte yüklü tüm modülleri (ad, taban adresi) listeler.
///
/// # Safety
///
///  geçerli ve okuma yetkisine sahip bir süreç handle'ı olmalıdır.
pub unsafe fn get_all_modules(
    invoker: &dyn SyscallInvoker,
    ntdll: *mut c_void,
    process_handle: *mut c_void,
) -> Vec<(String, usize)> {
    let mut modules = Vec::new();
    if process_handle.is_null() || process_handle == -1isize as *mut c_void || ntdll.is_null() {
        return modules;
    }

    let ssn_query = match get_ssn_by_hash(ntdll, dbj2_hash("NtQueryInformationProcess")) {
        Some(s) => s,
        None => return modules,
    };
    let ssn_read = match get_ssn_by_hash(ntdll, dbj2_hash("NtReadVirtualMemory")) {
        Some(s) => s,
        None => return modules,
    };

    let mut pbi = PROCESS_BASIC_INFORMATION::default();
    let mut ret_len = 0u32;
    let mut args_query: [usize; 11] = [
        process_handle as usize,
        0,
        &mut pbi as *mut _ as usize,
        std::mem::size_of::<PROCESS_BASIC_INFORMATION>(),
        &mut ret_len as *mut _ as usize,
        0, 0, 0, 0, 0, 0,
    ];

    let status = invoker.invoke(ssn_query, 0, &mut args_query);
    if status != 0 {
        return modules;
    }

    let peb_addr = pbi.peb_base_address as usize;
    if peb_addr == 0 {
        return modules;
    }

    #[cfg(target_arch = "x86_64")]
    {
        let mut ldr_ptr: usize = 0;
        if !read_remote(invoker, process_handle, ssn_read, peb_addr + 0x18, &mut ldr_ptr) || ldr_ptr == 0 {
            return modules;
        }

        let head_flink = ldr_ptr + 0x10;
        let mut current_entry: usize = 0;
        if !read_remote(invoker, process_handle, ssn_read, head_flink, &mut current_entry) || current_entry == 0 {
            return modules;
        }

        let mut iteration = 0;
        while current_entry != 0 && current_entry != head_flink {
            iteration += 1;
            if iteration > 500 {
                break;
            }

            let mut dll_base: usize = 0;
            if read_remote(invoker, process_handle, ssn_read, current_entry + 0x30, &mut dll_base) && dll_base != 0 {
                let mut name_unicode = UNICODE_STRING {
                    length: 0,
                    maximum_length: 0,
                    buffer: std::ptr::null_mut(),
                };

                if read_remote(
                    invoker,
                    process_handle,
                    ssn_read,
                    current_entry + 0x58,
                    &mut name_unicode,
                ) && !name_unicode.buffer.is_null()
                    && name_unicode.length > 0
                {
                    let name_len = (name_unicode.length / 2) as usize;
                    let mut name_buf = vec![0u16; name_len];
                    if read_remote_buffer(
                        invoker,
                        process_handle,
                        ssn_read,
                        name_unicode.buffer as usize,
                        name_buf.as_mut_ptr() as usize,
                        name_len * 2,
                    ) {
                        let name = String::from_utf16_lossy(&name_buf);
                        modules.push((name, dll_base));
                    }
                }
            }

            if !read_remote(invoker, process_handle, ssn_read, current_entry, &mut current_entry) {
                break;
            }
        }
    }

    modules
}

/// Uzak süreçteki bir adresin geçerli bir PE görüntüsü (DOS 'MZ' + NT 'PE\0\0') olup olmadığını doğrular.
unsafe fn is_valid_pe(
    invoker: &dyn SyscallInvoker,
    process_handle: *mut c_void,
    ssn_read: u16,
    base: usize,
) -> bool {
    let mut dos_magic: u16 = 0;
    if !read_remote(invoker, process_handle, ssn_read, base, &mut dos_magic) || dos_magic != 0x5A4D {
        return false;
    }

    let mut e_lfanew: i32 = 0;
    if !read_remote(invoker, process_handle, ssn_read, base + 0x3C, &mut e_lfanew)
        || e_lfanew <= 0
        || e_lfanew > 0x1000
    {
        return false;
    }

    let mut nt_sig: u32 = 0;
    if !read_remote(
        invoker,
        process_handle,
        ssn_read,
        base + e_lfanew as usize,
        &mut nt_sig,
    ) || nt_sig != 0x00004550
    {
        return false;
    }

    true
}
