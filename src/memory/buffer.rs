use crate::include::def::MEMORY_BASIC_INFORMATION;
use crate::include::def::{PAGE_EXECUTE_READWRITE, PAGE_READWRITE};
use crate::syscalls::SyscallInvoker;
use crate::syscalls::resolver::get_ssn_by_hash;
use crate::utils::dbj2_hash;
use std::ffi::c_void;
use std::mem;
use std::sync::atomic::{AtomicU16, Ordering};

static CACHED_READ_SSN: AtomicU16 = AtomicU16::new(0);

/// `NtReadVirtualMemory` SSN önbelleğini günceller.
pub fn set_read_ssn(ssn: u16) {
    if ssn != 0 && ssn != 0xFFFF {
        CACHED_READ_SSN.store(ssn, Ordering::Relaxed);
    }
}

/// `NtReadVirtualMemory` SSN'ini tek yerden çözer (önbellekli); bulunamazsa `None`.
unsafe fn read_ssn(ntdll: *mut c_void) -> Option<u16> {
    let cached = CACHED_READ_SSN.load(Ordering::Relaxed);
    if cached != 0 {
        return Some(cached);
    }
    if ntdll.is_null() {
        return None;
    }
    const HASH_NT_READ: u32 = dbj2_hash("NtReadVirtualMemory");
    let ssn = unsafe { get_ssn_by_hash(ntdll, HASH_NT_READ) }?;
    CACHED_READ_SSN.store(ssn, Ordering::Relaxed);
    Some(ssn)
}

/// Uzak belleğe yazma: gerekirse sayfa korumasını değiştirip yazar, sonra eski korumayı geri koyar.
///
/// # Safety
///
/// Çağıran, `address`in hedef süreçte eşlenmiş bir bölgeye ait olduğunu ve `data`nın `size`
/// baytının bu bölgeye sığdığını garanti etmelidir. Geçersiz adres `false` döndürür, ancak
/// bölge sınırları kontrol edilmez.
pub unsafe fn smart_write(
    invoker: &dyn SyscallInvoker,
    ntdll: *mut c_void,
    process_handle: *mut c_void,
    target_address: *mut c_void,
    data: &[u8],
) -> bool {
    unsafe {
        if process_handle.is_null() || target_address.is_null() || data.is_empty() {
            return false;
        }
        if ntdll.is_null() {
            return false;
        }

        const HASH_NT_QUERY_VM: u32 = dbj2_hash("NtQueryVirtualMemory");
        const HASH_NT_PROTECT_VM: u32 = dbj2_hash("NtProtectVirtualMemory");
        const HASH_NT_WRITE_VM: u32 = dbj2_hash("NtWriteVirtualMemory");

        let ssn_query = match get_ssn_by_hash(ntdll, HASH_NT_QUERY_VM) {
            Some(ssn) => ssn,
            None => return false,
        };
        let ssn_protect = match get_ssn_by_hash(ntdll, HASH_NT_PROTECT_VM) {
            Some(ssn) => ssn,
            None => return false,
        };
        let ssn_write = match get_ssn_by_hash(ntdll, HASH_NT_WRITE_VM) {
            Some(ssn) => ssn,
            None => return false,
        };

        let mut mbi = std::mem::zeroed::<MEMORY_BASIC_INFORMATION>();
        let mut args_query: [usize; 11] = [
            process_handle as usize,
            target_address as usize,
            0,
            &mut mbi as *mut _ as usize,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            0,
            0, 0, 0, 0, 0,
        ];
        let query_status = invoker.invoke(ssn_query, 0, &mut args_query);
        if query_status != 0 {
            return false;
        }

        let mut old_protect: u32 = 0;
        let needs_protect =
            (mbi.protect & PAGE_READWRITE) == 0 && (mbi.protect & PAGE_EXECUTE_READWRITE) == 0;

        if needs_protect {
            let mut protect_addr = target_address;
            let mut protect_size = data.len();
            let mut args_protect: [usize; 11] = [
                process_handle as usize,
                &mut protect_addr as *mut _ as usize,
                &mut protect_size as *mut _ as usize,
                PAGE_EXECUTE_READWRITE as usize,
                &mut old_protect as *mut _ as usize,
                0, 0, 0, 0, 0, 0,
            ];
            let protect_status = invoker.invoke(ssn_protect, 0, &mut args_protect);
            if protect_status != 0 {
                return false;
            }
        }

        let mut bytes_written: usize = 0;
        let mut args_write: [usize; 11] = [
            process_handle as usize,
            target_address as usize,
            data.as_ptr() as usize,
            data.len(),
            &mut bytes_written as *mut _ as usize,
            0, 0, 0, 0, 0, 0,
        ];
        let write_status = invoker.invoke(ssn_write, 0, &mut args_write);
        // Kısmi yazma da başarısızlıktır: çağıran "tamamı yazıldı" varsayımıyla devam etmemeli.
        let success = write_status == 0 && bytes_written == data.len();

        if needs_protect {
            let mut protect_addr = target_address;
            let mut protect_size = data.len();
            let mut junk_protect: u32 = 0;
            let mut args_restore: [usize; 11] = [
                process_handle as usize,
                &mut protect_addr as *mut _ as usize,
                &mut protect_size as *mut _ as usize,
                old_protect as usize,
                &mut junk_protect as *mut _ as usize,
                0, 0, 0, 0, 0, 0,
            ];
            // Koruma geri alınamazsa yazma yine de "başarılı" sayılır, ama sessizce yutulmaz:
            // hata durumu bool dönüşüne yansıtılır.
            let restore_status = invoker.invoke(ssn_protect, 0, &mut args_restore);
            if restore_status != 0 {
                return false;
            }
        }

        success
    }
}

/// Uzak belleğe `T` yazar.
///
/// # Safety
///
/// `address` hedef süreçte yazılabilir (veya koruması kaldırılabilir) bir adres olmalıdır. `T`
/// içinde geçerli işaretçi bulunmamalıdır (aksi halde hedef süreçte çöp işaretçi kalır).
pub unsafe fn write<T>(
    invoker: &dyn SyscallInvoker,
    ntdll: *mut c_void,
    process_handle: *mut c_void,
    address: usize,
    value: T,
) -> bool {
    unsafe {
        let data =
            std::slice::from_raw_parts(&value as *const T as *const u8, mem::size_of::<T>());
        smart_write(invoker, ntdll, process_handle, address as *mut c_void, data)
    }
}

/// Uzak bellekten `size` baytlık ham okuma; hata durumunda boş `Vec`.
///
/// # Safety
///
/// `address` hedef süreçte okunabilir olmalı; `size` çağıranın kendi bellek bütçesine göre
/// makul olmalıdır (keyfi büyük `size` OOM'a yol açar).
pub unsafe fn read_buffers(
    invoker: &dyn SyscallInvoker,
    ntdll: *mut c_void,
    process_handle: *mut c_void,
    address: usize,
    size: usize,
) -> Vec<u8> {
    let mut buffer = vec![0u8; size];
    let mut bytes_read = 0usize;

    let ssn = match unsafe { read_ssn(ntdll) } {
        Some(ssn) => ssn,
        None => return Vec::new(),
    };

    let mut args: [usize; 11] = [
        process_handle as usize,
        address,
        buffer.as_mut_ptr() as usize,
        size,
        &mut bytes_read as *mut _ as usize,
        0, 0, 0, 0, 0, 0,
    ];

    let status = unsafe { invoker.invoke(ssn, 0, &mut args) };
    if status != 0 || bytes_read != size {
        return Vec::new();
    }

    buffer
}

/// Uzak bellekten `size` baytlık okuma.
///
/// # Safety
///
/// `address..address+size` hedef süreçte commit edilmiş ve okunabilir olmalıdır. Kısmi okuma
/// başarısız sayılır ve boş `Vec` döner.
pub unsafe fn read_buffer(
    invoker: &dyn SyscallInvoker,
    ntdll: *mut c_void,
    process_handle: *mut c_void,
    address: usize,
    buffer: &mut [u8],
) -> bool {
    unsafe {
        let ssn_read = match read_ssn(ntdll) {
            Some(ssn) => ssn,
            None => return false,
        };

        let mut bytes_read: usize = 0;
        let mut args: [usize; 11] = [
            process_handle as usize,
            address,
            buffer.as_mut_ptr() as usize,
            buffer.len(),
            &mut bytes_read as *mut usize as usize,
            0, 0, 0, 0, 0, 0,
        ];

        let status = invoker.invoke(ssn_read, 0, &mut args);
        status == 0 && bytes_read == buffer.len()
    }
}

/// Uzak bellekten isteğe bağlı okuma (`Option`).
///
/// # Safety
///
/// `read_buffer` ile aynı sözleşme: aralık hedef süreçte okunabilir olmalı; kısmi okuma `None`
/// döner.
pub unsafe fn read_bytes(
    invoker: &dyn SyscallInvoker,
    ntdll: *mut c_void,
    process_handle: *mut c_void,
    address: usize,
    size: usize,
) -> Vec<u8> {
    let mut buffer = vec![0u8; size];
    let succes = unsafe { read_buffer(invoker, ntdll, process_handle, address, &mut buffer) };
    if succes { buffer } else { Vec::new() }
}

/// Uzak bellekten `T` okur.
///
/// # Safety
///
/// `address` hedef süreçte `size_of::<T>()` kadar okunabilir olmalı ve `T` POD (düz veri)
/// olmalıdır. Okuma başarısız olursa sıfırlanmış `T` döner, bu yüzden dönüş değeri tek başına
/// başarı kanıtı değildir.
pub unsafe fn read<T>(
    invoker: &dyn SyscallInvoker,
    ntdll: *mut c_void,
    process_handle: *mut c_void,
    address: usize,
) -> T {
    unsafe {
        let mut buffer: T = mem::zeroed();
        let ssn_read = match read_ssn(ntdll) {
            Some(ssn) => ssn,
            None => return buffer,
        };

        let mut bytes_read: usize = 0;
        let mut args: [usize; 11] = [
            process_handle as usize,
            address,
            &mut buffer as *mut T as usize,
            mem::size_of::<T>(),
            &mut bytes_read as *mut usize as usize,
            0, 0, 0, 0, 0, 0,
        ];

        let status = invoker.invoke(ssn_read, 0, &mut args);
        if status != 0 || bytes_read != mem::size_of::<T>() {
            return mem::zeroed();
        }
        buffer
    }
}
