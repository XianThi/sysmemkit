use crate::utils;
use crate::include::def::*;
use crate::syscalls::{Ssn, SsnResolver};
use std::ffi::c_void;
use std::arch::asm;

/// PEB modül listesinden belirtilen DLL'in taban adresini ve boyutunu döner.
///
/// # Safety
///
/// Yalnızca geçerli bir PEB ortamında ve x86_64 sürecinde çağrılmalıdır.
pub unsafe fn get_dll_base(modulename: &str) -> (*mut c_void, usize) {
    let peb_ptr: *mut PEB;
    unsafe {
        asm!(
            "mov {}, gs:[0x60]",
            out(reg) peb_ptr,
            options(nostack, readonly)
        );

        if peb_ptr.is_null() {
            return (std::ptr::null_mut(), 0);
        }

        let ldr = (*peb_ptr).ldr;
        if ldr.is_null() {
            return (std::ptr::null_mut(), 0);
        }

        let list_head = &(*ldr).in_load_order_module_list as *const LIST_ENTRY as *mut LIST_ENTRY;
        let mut current = (*list_head).flink;

        while current != list_head {
            let entry = current as *mut LDR_DATA_TABLE_ENTRY;

            if !entry.is_null() && !(*entry).dll_base.is_null() {
                let dll_name = &(*entry).base_dll_name;

                if !dll_name.buffer.is_null() && dll_name.length > 0 {
                    let name_len = (dll_name.length / 2) as usize;
                    let name_slice = std::slice::from_raw_parts(dll_name.buffer, name_len);
                    let name = String::from_utf16_lossy(name_slice);

                    if name.to_lowercase() == modulename {
                        let dll_base = (*entry).dll_base;
                        let size_of_image = (*entry).size_of_image;
                        return (dll_base, size_of_image as usize);
                    }
                }
            }

            current = (*current).flink;
        }

        (std::ptr::null_mut(), 0)
    }
}

/// PEB üzerinden ntdll image tabanını ve boyutunu döndürür.
///
/// # Safety
///
/// Yalnızca Windows x64 süreçte çağrılmalıdır; PEB ve InLoadOrder listesi okunur. PEB'in
/// geçerli olduğu varsayılır.
pub unsafe fn get_ntdll_base() -> (*mut c_void, usize) {
    unsafe { get_dll_base("ntdll.dll") }
}

// Faz 1'de feature flag arkasına alınacak; şu an sadece deney kodunda kullanılıyor.
#[allow(dead_code)]
/// win32u.dll taban adresini ve boyutunu döner.
///
/// # Safety
///
/// PEB üzerinde yürütülür; geçerli bir Windows süreci gerektirir.
pub unsafe fn get_win32u_base() -> (*mut c_void, usize) {
    unsafe { get_dll_base("win32u.dll") }
}

/// Teşhis: bir export fonksiyonunun ilk baytlarını döker.
///
/// # Safety
///
/// `ntdll_base` eşlenmiş ntdll image tabanını göstermelidir; fonksiyon sadece teşhis amaçlı
/// bayt döker.
pub unsafe fn print_function_bytes(ntdll_base: *mut c_void, func_name: &str) {
    if ntdll_base.is_null() {
        return;
    }
    unsafe {
        let dos_header = ntdll_base as *const IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != 0x5A4D {
            return;
        }

        let nt_headers =
            (ntdll_base as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        let export_dir_rva = (*nt_headers).optional_header.data_directory[0].virtual_address;
        let export_dir =
            (ntdll_base as usize + export_dir_rva as usize) as *const IMAGE_EXPORT_DIRECTORY;

        let names_ptr =
            (ntdll_base as usize + (*export_dir).address_of_names as usize) as *const u32;
        let functions_ptr =
            (ntdll_base as usize + (*export_dir).address_of_functions as usize) as *const u32;
        let ordinals_ptr =
            (ntdll_base as usize + (*export_dir).address_of_name_ordinals as usize) as *const u16;

        let num_names = (*export_dir).number_of_names;

        for i in 0..num_names {
            let name_rva = *names_ptr.add(i as usize);
            let name_ptr = (ntdll_base as usize + name_rva as usize) as *const i8;
            let current_name = std::ffi::CStr::from_ptr(name_ptr).to_str().unwrap_or("");

            if current_name == func_name {
                let ordinal = *ordinals_ptr.add(i as usize);
                let func_rva = *functions_ptr.add(ordinal as usize);
                let func_addr = (ntdll_base as usize + func_rva as usize) as *const u8;

                print!("İlk 32 byte: ");
                for j in 0..32 {
                    print!("{:02X} ", *func_addr.add(j));
                }

                break;
            }
        }
    }
}

/// Export adı hash'inden syscall numarasını (SSN) çözer.
///
/// # Safety
///
/// `ntdll_base` eşlenmiş ntdll image tabanı olmalı ve export dizini okunabilir olmalıdır.
/// Bulunamazsa `None` döner (SSN 0 döndürülmez: 0 geçerli bir syscall numarasıdır).
pub unsafe fn get_ssn_by_hash(ntdll_base: *mut c_void, target_hash: u32) -> Option<u16> {
    if ntdll_base.is_null() {
        return None;
    }
    unsafe {
        let dos_header = ntdll_base as *const IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != 0x5A4D {
            //MZ
            return None;
        }

        let nt_headers =
            (ntdll_base as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        if (*nt_headers).signature != 0x00004550 {
            return None;
        }

        let export_dir_rva = (*nt_headers).optional_header.data_directory[0].virtual_address;
        if export_dir_rva == 0 {
            return None;
        }

        let export_dir =
            (ntdll_base as usize + export_dir_rva as usize) as *const IMAGE_EXPORT_DIRECTORY;

        let names_ptr =
            (ntdll_base as usize + (*export_dir).address_of_names as usize) as *const u32;
        let functions_ptr =
            (ntdll_base as usize + (*export_dir).address_of_functions as usize) as *const u32;
        let ordinals_ptr =
            (ntdll_base as usize + (*export_dir).address_of_name_ordinals as usize) as *const u16;

        let num_names = (*export_dir).number_of_names;

        for i in 0..num_names {
            let name_rva = *names_ptr.add(i as usize);
            let name_ptr = (ntdll_base as usize + name_rva as usize) as *const i8;

            let current_name = match std::ffi::CStr::from_ptr(name_ptr).to_str() {
                Ok(name) => name,
                Err(_) => continue,
            };

            let current_hash = utils::dbj2_hash(current_name);

            if current_hash == target_hash {
                let ordinal = *ordinals_ptr.add(i as usize);
                let func_rva = *functions_ptr.add(ordinal as usize);
                let func_addr = (ntdll_base as usize + func_rva as usize) as *const u8;

                for offset in 0..32 {
                    let byte = *func_addr.add(offset);

                    if byte == 0xB8 {
                        let ssn = *(func_addr.add(offset + 1) as *const u16);
                        if ssn != 0 && ssn != 0xFFFF {
                            return Some(ssn);
                        }
                    }

                    if offset + 4 < 32
                        && *func_addr.add(offset) == 0x4C
                        && *func_addr.add(offset + 1) == 0x8B
                        && *func_addr.add(offset + 2) == 0xD1
                        && *func_addr.add(offset + 3) == 0xB8
                    {
                        let ssn = *(func_addr.add(offset + 4) as *const u16);
                        if ssn != 0 && ssn != 0xFFFF {
                            return Some(ssn);
                        }
                    }
                }

                // SSN bulunamadı: 0 döndürmek NtAccessCheck'i çağırmak demektir.
                // Sessiz yanlış syscall yerine açık başarısızlık.
                return None;
            }
        }

        None
    }
}

/// SSN çözümü için sarmalayıcı (hash → numara).
///
/// # Safety
///
/// `get_ssn_by_hash` ile aynı sözleşme; ek olarak fonksiyon gövdesi `E9` (hook) ile başlıyorsa
/// SSN güvenilmez olabilir.
pub unsafe fn get_syscall_number(ntdll_base: *mut c_void, func_hash: u32) -> Option<u16> {
    unsafe {
        if ntdll_base.is_null() {
            return None;
        }
        get_ssn_by_hash(ntdll_base, func_hash)
    }
}

/// Export adı hash'inden hem syscall numarasını (SSN) hem de stub içindeki `syscall` (`0F 05 C3`)
/// adresini çözer (Faz 3).
///
/// # Safety
///
/// `ntdll_base` eşlenmiş ntdll image tabanı olmalı ve export dizini okunabilir olmalıdır.
pub unsafe fn get_ssn_stub_by_hash(ntdll_base: *mut c_void, target_hash: u32) -> Option<Ssn> {
    if ntdll_base.is_null() {
        return None;
    }
    let (func_addr, _) = find_export_by_hash(ntdll_base, target_hash)?;
    let func_ptr = func_addr;

    // 1. Doğrudan temiz stub kontrolü: kendi stub'ındaki syscall adresini al
    if !unsafe { is_stub_hooked(func_ptr) }
        && let Some(ssn) = unsafe { extract_clean_ssn(func_ptr) }
    {
        let stub = unsafe { find_syscall_in_stub(func_ptr) }.unwrap_or(func_addr as usize);
        return Some(Ssn { number: ssn, stub });
    }

    // 2. Hook'lu ise Halo's Gate / Tartarus' Gate ile komşunun syscall adresini al
    if let Some((text_start, text_end)) = unsafe { get_text_section_bounds(ntdll_base) }
        && let Some((ssn, stub)) =
            unsafe { halos_tartarus_walk_with_stub(func_addr as usize, text_start, text_end) }
    {
        return Some(Ssn { number: ssn, stub });
    }

    // 3. Basit 0xB8 taraması fallback
    unsafe {
        for offset in 0..32 {
            let byte = *func_ptr.add(offset);
            if byte == 0xB8 {
                let ssn = *(func_ptr.add(offset + 1) as *const u16);
                if ssn != 0 && ssn != 0xFFFF {
                    let stub = find_syscall_in_stub(func_ptr).unwrap_or(func_addr as usize);
                    return Some(Ssn { number: ssn, stub });
                }
            }
        }
    }

    None
}

// İsimden SSN çözümü: test/teşhis yardımcısı.
#[allow(dead_code)]
/// Fonksiyon adına göre SSN numarasını arar.
///
/// # Safety
///
/// `ntdll_base` geçerli bir PE görüntüsünü göstermelidir.
pub unsafe fn get_syscall_number_by_name(ntdll_base: *mut c_void, func_name: &str) -> Option<u16> {
    unsafe {
        let hash = utils::dbj2_hash(func_name);
        get_syscall_number(ntdll_base, hash)
    }
}


/// Mode::Basic için ntdll export tablosundan `0xB8` bayt taraması yapan saf çözücü.
///
/// Hook kontrolü (`0xE9`) yapmaz; eğitim amaçlı temel çözücüdür.
#[derive(Debug, Clone, Copy)]
pub struct ExportByteResolver {
    ntdll_base: *mut c_void,
}

unsafe impl Send for ExportByteResolver {}
unsafe impl Sync for ExportByteResolver {}

impl ExportByteResolver {
    /// ntdll taban adresini döner.
    pub fn ntdll_base(&self) -> *mut c_void {
        self.ntdll_base
    }

    /// ntdll taban adresinden FreshyCalls ve HookAware çözücüleri başlatır.
    ///
    /// # Safety
    ///
    /// `ntdll_base` geçerli bir ntdll PE görüntüsünü göstermelidir.
    pub unsafe fn new(ntdll_base: *mut c_void) -> Self {
        Self { ntdll_base }
    }
}

impl SsnResolver for ExportByteResolver {
    fn resolve(&self, name_hash: u32) -> Option<Ssn> {
        if self.ntdll_base.is_null() {
            return None;
        }
        unsafe {
            let (func_addr, _) = find_export_by_hash(self.ntdll_base, name_hash)?;
            // Saf 0xB8 taraması (hook kontrolü yok)
            for offset in 0..32 {
                let byte = *func_addr.add(offset);
                if byte == 0xB8 {
                    let ssn = *(func_addr.add(offset + 1) as *const u16);
                    if ssn != 0 && ssn != 0xFFFF {
                        let stub =
                            find_syscall_in_stub(func_addr).unwrap_or(func_addr as usize);
                        return Some(Ssn {
                            number: ssn,
                            stub,
                        });
                    }
                }
            }
            None
        }
    }
}

/// Bir syscall stub'ının hook'lanıp hook'lanmadığını tespit eder.
///
/// Kontrol edilen desenler:
/// - Offset 0: `0xE9` (jmp rel32), `0xEB` (jmp rel8), `0xE8` (call rel32)
/// - Offset 0: `48 FF 25` / `FF 25` (jmp [rip + disp32])
/// - Tartarus' Gate: Offset 1..16 arasında `0xE9`, `48 FF 25`, `FF 25`, `0xEB`, `0xE8`
/// - Tartarus' Gate: `4C 8B D1` (mov r10, rcx) sonrasında `0xB8` (mov eax, ssn) gelmemesi
///
/// # Safety
///
/// `stub_ptr` en az 32 bayt okunabilir bellek alanını göstermelidir.
pub unsafe fn is_stub_hooked(stub_ptr: *const u8) -> bool {
    let b0 = *stub_ptr;
    if b0 == 0xE9 || b0 == 0xEB || b0 == 0xE8 {
        return true;
    }
    if b0 == 0x48 && *stub_ptr.add(1) == 0xFF && *stub_ptr.add(2) == 0x25 {
        return true;
    }
    if b0 == 0xFF && *stub_ptr.add(1) == 0x25 {
        return true;
    }

    for offset in 1..16 {
        let b = *stub_ptr.add(offset);
        if b == 0xE9 || b == 0xEB || b == 0xE8 {
            return true;
        }
        if offset + 2 < 16
            && b == 0x48
            && *stub_ptr.add(offset + 1) == 0xFF
            && *stub_ptr.add(offset + 2) == 0x25
        {
            return true;
        }
        if offset + 1 < 16 && b == 0xFF && *stub_ptr.add(offset + 1) == 0x25 {
            return true;
        }
    }

    if *stub_ptr == 0x4C
        && *stub_ptr.add(1) == 0x8B
        && *stub_ptr.add(2) == 0xD1
        && *stub_ptr.add(3) != 0xB8
    {
        return true;
    }

    false
}

/// Temiz ve hook'lanmamış bir syscall stub'ından SSN numarasını ayıklar.
///
/// # Safety
///
/// `stub_ptr` en az 32 bayt okunabilir bellek alanını göstermelidir.
pub unsafe fn extract_clean_ssn(stub_ptr: *const u8) -> Option<u16> {
    if is_stub_hooked(stub_ptr) {
        return None;
    }

    if *stub_ptr == 0x4C
        && *stub_ptr.add(1) == 0x8B
        && *stub_ptr.add(2) == 0xD1
        && *stub_ptr.add(3) == 0xB8
    {
        let ssn = *(stub_ptr.add(4) as *const u16);
        if ssn != 0 && ssn != 0xFFFF {
            return Some(ssn);
        }
    }

    for offset in 0..16 {
        if *stub_ptr.add(offset) == 0xB8 {
            let ssn = *(stub_ptr.add(offset + 1) as *const u16);
            if ssn != 0 && ssn != 0xFFFF {
                return Some(ssn);
            }
        }
    }

    None
}

/// ntdll görüntüsünün `.text` (kod) bölümünün sınırlarını döner.
///
/// # Safety
///
/// `ntdll_base` geçerli bir PE görüntüsünü göstermelidir.
pub unsafe fn get_text_section_bounds(ntdll_base: *mut c_void) -> Option<(usize, usize)> {
    if ntdll_base.is_null() {
        return None;
    }
    let dos_header = ntdll_base as *const IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != 0x5A4D {
        return None;
    }
    let nt_headers =
        (ntdll_base as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    if (*nt_headers).signature != 0x00004550 {
        return None;
    }
    let base_of_code = (*nt_headers).optional_header.base_of_code as usize;
    let size_of_code = (*nt_headers).optional_header.size_of_code as usize;
    if base_of_code == 0 || size_of_code == 0 {
        return None;
    }
    let text_start = ntdll_base as usize + base_of_code;
    let text_end = text_start + size_of_code;
    Some((text_start, text_end))
}

/// Bir stub (en fazla 32 bayt) içinde `0F 05` (`syscall`) komutunun adresini arar.
///
/// # Safety
///
/// `stub_ptr` okunabilir bellek göstermelidir.
pub unsafe fn find_syscall_in_stub(stub_ptr: *const u8) -> Option<usize> {
    if stub_ptr.is_null() {
        return None;
    }
    for offset in 0..30 {
        if *stub_ptr.add(offset) == 0x0F && *stub_ptr.add(offset + 1) == 0x05 {
            return Some(stub_ptr.add(offset) as usize);
        }
    }
    None
}

/// Hook'lu bir stub'ın en yakın temiz komşusundaki `syscall` (`0F 05`) adresini bulur.
///
/// # Safety
///
/// `target_addr` ve sınırlar geçerli ntdll bellek alanını göstermelidir.
pub unsafe fn find_clean_neighbor_syscall(
    target_addr: usize,
    text_start: usize,
    text_end: usize,
) -> Option<usize> {
    const STUB_SIZE: usize = 32;

    for k in 1..=64 {
        // Aşağı komşu (+k)
        let down_addr = target_addr
            .checked_add(k * STUB_SIZE)
            .filter(|&addr| addr >= text_start && addr + STUB_SIZE <= text_end);
        if let Some(addr) = down_addr {
            let neighbor_ptr = addr as *const u8;
            if !is_stub_hooked(neighbor_ptr)
                && let Some(sc) = find_syscall_in_stub(neighbor_ptr)
            {
                return Some(sc);
            }
        }

        // Yukarı komşu (-k)
        let up_addr = target_addr
            .checked_sub(k * STUB_SIZE)
            .filter(|&addr| addr >= text_start && addr + STUB_SIZE <= text_end);
        if let Some(addr) = up_addr {
            let neighbor_ptr = addr as *const u8;
            if !is_stub_hooked(neighbor_ptr)
                && let Some(sc) = find_syscall_in_stub(neighbor_ptr)
            {
                return Some(sc);
            }
        }
    }

    None
}

/// Halo's Gate ve Tartarus' Gate ile komşu stub'ları tarar; hem SSN'i hem de temiz komşunun
/// `syscall` adresini döner.
///
/// # Safety
///
/// `target_addr` ve sınırlar geçerli ntdll bellek alanını göstermelidir.
pub unsafe fn halos_tartarus_walk_with_stub(
    target_addr: usize,
    text_start: usize,
    text_end: usize,
) -> Option<(u16, usize)> {
    const STUB_SIZE: usize = 32;

    for k in 1..=64 {
        // Aşağı komşu (+k): Adres artar, SSN artar -> target_ssn = neighbor_ssn - k
        let down_addr = target_addr
            .checked_add(k * STUB_SIZE)
            .filter(|&addr| addr >= text_start && addr + STUB_SIZE <= text_end);
        if let Some(addr) = down_addr {
            let neighbor_ptr = addr as *const u8;
            let target_ssn = extract_clean_ssn(neighbor_ptr)
                .and_then(|ssn| ssn.checked_sub(k as u16));
            if let Some(ssn) = target_ssn {
                let stub = find_syscall_in_stub(neighbor_ptr).unwrap_or(addr);
                return Some((ssn, stub));
            }
        }

        // Yukarı komşu (-k): Adres azalır, SSN azalır -> target_ssn = neighbor_ssn + k
        let up_addr = target_addr
            .checked_sub(k * STUB_SIZE)
            .filter(|&addr| addr >= text_start && addr + STUB_SIZE <= text_end);
        if let Some(addr) = up_addr {
            let neighbor_ptr = addr as *const u8;
            let target_ssn = extract_clean_ssn(neighbor_ptr)
                .and_then(|ssn| ssn.checked_add(k as u16));
            if let Some(ssn) = target_ssn {
                let stub = find_syscall_in_stub(neighbor_ptr).unwrap_or(addr);
                return Some((ssn, stub));
            }
        }
    }

    None
}

/// Halo's Gate ve Tartarus' Gate algoritmalarını birleştirerek komşu stub'lar üzerinden SSN hesaplar.
///
/// # Safety
///
/// `target_addr` ve sınırlar geçerli ntdll bellek alanını göstermelidir.
pub unsafe fn halos_tartarus_walk(
    target_addr: usize,
    text_start: usize,
    text_end: usize,
) -> Option<u16> {
    unsafe { halos_tartarus_walk_with_stub(target_addr, text_start, text_end).map(|(ssn, _)| ssn) }
}

/// FreshyCalls yaklaşımıyla ntdll export tablosundaki `Zw*` fonksiyonlarını
/// RVA'ya göre sıralayarak SSN çözen çözücü.
///
/// Fonksiyon gövdelerindeki baytlara dokunmaz; in-memory hook'lardan (`0xE9`)
/// tamamen etkilenmez.
#[derive(Debug, Clone)]
pub struct ExportRvaResolver {
    #[allow(dead_code)]
    ntdll_base: *mut c_void,
    cache: Vec<(u32, Ssn)>,
}

unsafe impl Send for ExportRvaResolver {}
unsafe impl Sync for ExportRvaResolver {}

impl ExportRvaResolver {
    /// ntdll taban adresinden export dizinini okuyarak RVA sıralı SSN tablosunu oluşturur.
    ///
    /// # Safety
    ///
    /// `ntdll_base` geçerli bir ntdll PE görüntüsünü göstermelidir.
    pub unsafe fn new(ntdll_base: *mut c_void) -> Self {
        if ntdll_base.is_null() {
            return Self {
                ntdll_base,
                cache: Vec::new(),
            };
        }

        let cache = unsafe { Self::build_rva_table(ntdll_base) };
        Self { ntdll_base, cache }
    }

    unsafe fn build_rva_table(ntdll_base: *mut c_void) -> Vec<(u32, Ssn)> {
        let dos_header = ntdll_base as *const IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != 0x5A4D {
            return Vec::new();
        }

        let nt_headers =
            (ntdll_base as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        if (*nt_headers).signature != 0x00004550 {
            return Vec::new();
        }

        let export_dir_rva = (*nt_headers).optional_header.data_directory[0].virtual_address;
        if export_dir_rva == 0 {
            return Vec::new();
        }

        let export_dir =
            (ntdll_base as usize + export_dir_rva as usize) as *const IMAGE_EXPORT_DIRECTORY;

        let names_ptr =
            (ntdll_base as usize + (*export_dir).address_of_names as usize) as *const u32;
        let functions_ptr =
            (ntdll_base as usize + (*export_dir).address_of_functions as usize) as *const u32;
        let ordinals_ptr =
            (ntdll_base as usize + (*export_dir).address_of_name_ordinals as usize) as *const u16;

        let num_names = (*export_dir).number_of_names;

        struct ExportEntry {
            rva: u32,
            func_addr: usize,
            hashes: Vec<u32>,
        }

        let mut zw_entries: Vec<ExportEntry> = Vec::new();

        for i in 0..num_names {
            let name_rva = *names_ptr.add(i as usize);
            let name_ptr = (ntdll_base as usize + name_rva as usize) as *const i8;

            let name = match std::ffi::CStr::from_ptr(name_ptr).to_str() {
                Ok(s) => s,
                Err(_) => continue,
            };

            if let Some(suffix) = name.strip_prefix("Zw") {
                let ordinal = *ordinals_ptr.add(i as usize);
                let func_rva = *functions_ptr.add(ordinal as usize);
                let func_addr = ntdll_base as usize + func_rva as usize;

                let zw_hash = utils::dbj2_hash(name);
                let nt_name = format!("Nt{suffix}");
                let nt_hash = utils::dbj2_hash(&nt_name);

                if let Some(existing) = zw_entries.iter_mut().find(|e| e.rva == func_rva) {
                    if !existing.hashes.contains(&zw_hash) {
                        existing.hashes.push(zw_hash);
                    }
                    if !existing.hashes.contains(&nt_hash) {
                        existing.hashes.push(nt_hash);
                    }
                } else {
                    zw_entries.push(ExportEntry {
                        rva: func_rva,
                        func_addr,
                        hashes: vec![zw_hash, nt_hash],
                    });
                }
            }
        }

        // Nt* export'larını da kontrol et ve eşleşen RVA'lara hash ekle
        for i in 0..num_names {
            let name_rva = *names_ptr.add(i as usize);
            let name_ptr = (ntdll_base as usize + name_rva as usize) as *const i8;

            let name = match std::ffi::CStr::from_ptr(name_ptr).to_str() {
                Ok(s) => s,
                Err(_) => continue,
            };

            if name.starts_with("Nt") {
                let ordinal = *ordinals_ptr.add(i as usize);
                let func_rva = *functions_ptr.add(ordinal as usize);
                let nt_hash = utils::dbj2_hash(name);

                if let Some(existing) = zw_entries
                    .iter_mut()
                    .find(|e| e.rva == func_rva && !e.hashes.contains(&nt_hash))
                {
                    existing.hashes.push(nt_hash);
                }
            }
        }

        // RVA'ya göre küçükten büyüğe sırala (FreshyCalls prensibi)
        zw_entries.sort_by_key(|e| e.rva);

        let (text_start, text_end) =
            get_text_section_bounds(ntdll_base).unwrap_or((0, usize::MAX));

        let mut cache: Vec<(u32, Ssn)> = Vec::with_capacity(zw_entries.len() * 2);
        for (index, entry) in zw_entries.into_iter().enumerate() {
            let func_ptr = entry.func_addr as *const u8;
            let stub = if !is_stub_hooked(func_ptr) {
                find_syscall_in_stub(func_ptr).unwrap_or(entry.func_addr)
            } else if text_start < text_end {
                find_clean_neighbor_syscall(entry.func_addr, text_start, text_end)
                    .unwrap_or(entry.func_addr)
            } else {
                entry.func_addr
            };
            let ssn = Ssn {
                number: index as u16,
                stub,
            };
            for hash in entry.hashes {
                cache.push((hash, ssn));
            }
        }

        cache.sort_by_key(|(h, _)| *h);
        cache.dedup_by_key(|(h, _)| *h);
        cache
    }
}

impl SsnResolver for ExportRvaResolver {
    fn resolve(&self, name_hash: u32) -> Option<Ssn> {
        self.cache
            .binary_search_by_key(&name_hash, |(h, _)| *h)
            .ok()
            .map(|idx| self.cache[idx].1)
    }
}

/// Hook tespit yeteneğine ve Halo's / Tartarus' Gate komşu taramasına sahip SSN çözücü.
#[derive(Debug, Clone, Copy)]
pub struct HookAwareResolver {
    ntdll_base: *mut c_void,
}

unsafe impl Send for HookAwareResolver {}
unsafe impl Sync for HookAwareResolver {}

impl HookAwareResolver {
    /// ntdll taban adresinden FreshyCalls ve HookAware çözücüleri başlatır.
    ///
    /// # Safety
    ///
    /// `ntdll_base` geçerli bir ntdll PE görüntüsünü göstermelidir.
    pub unsafe fn new(ntdll_base: *mut c_void) -> Self {
        Self { ntdll_base }
    }

    /// Hedef fonksiyonun gövdesinde hook yoksa temiz SSN'i döner.
    ///
    /// # Safety
    ///
    /// `ntdll_base` geçerli bir ntdll PE görüntüsü olmalıdır.
    pub unsafe fn resolve_clean(&self, name_hash: u32) -> Option<Ssn> {
        if self.ntdll_base.is_null() {
            return None;
        }
        let (func_addr, _) = find_export_by_hash(self.ntdll_base, name_hash)?;
        let ssn_num = extract_clean_ssn(func_addr)?;
        let stub = find_syscall_in_stub(func_addr).unwrap_or(func_addr as usize);
        Some(Ssn {
            number: ssn_num,
            stub,
        })
    }

    /// Hedef fonksiyon hook'luysa Halo's Gate ve Tartarus' Gate ile komşulardan SSN hesaplar.
    ///
    /// # Safety
    ///
    /// `ntdll_base` geçerli bir ntdll PE görüntüsü olmalıdır.
    pub unsafe fn resolve_halos_tartarus(&self, name_hash: u32) -> Option<Ssn> {
        if self.ntdll_base.is_null() {
            return None;
        }
        let (func_addr, _) = find_export_by_hash(self.ntdll_base, name_hash)?;
        let (text_start, text_end) = get_text_section_bounds(self.ntdll_base)?;
        let (ssn_num, stub) =
            halos_tartarus_walk_with_stub(func_addr as usize, text_start, text_end)?;
        Some(Ssn {
            number: ssn_num,
            stub,
        })
    }
}

impl SsnResolver for HookAwareResolver {
    fn resolve(&self, name_hash: u32) -> Option<Ssn> {
        if self.ntdll_base.is_null() {
            return None;
        }
        unsafe {
            // Önce doğrudan temiz stub kontrolü
            if let Some(ssn) = self.resolve_clean(name_hash) {
                return Some(ssn);
            }

            // Hook tespit edilirse Halo's Gate ve Tartarus' Gate komşu aramasını uygula
            self.resolve_halos_tartarus(name_hash)
        }
    }
}

/// Mode::DirectStealth için birleşik hook-dayanıklı SSN çözücü.
///
/// Çözümleme sırası:
/// 1. `ExportRvaResolver` (FreshyCalls: disk ve hook bağımsız RVA sıralaması)
/// 2. `HookAwareResolver` doğrudan temiz stub kontrolü (`0xB8`)
/// 3. Halo's Gate / Tartarus' Gate komşu stub taraması (±32*k)
#[derive(Debug, Clone)]
pub struct DirectStealthResolver {
    export_rva: ExportRvaResolver,
    hook_aware: HookAwareResolver,
}

unsafe impl Send for DirectStealthResolver {}
unsafe impl Sync for DirectStealthResolver {}

impl DirectStealthResolver {
    /// ntdll taban adresinden FreshyCalls ve HookAware çözücüleri başlatır.
    ///
    /// # Safety
    ///
    /// `ntdll_base` geçerli bir ntdll PE görüntüsünü göstermelidir.
    pub unsafe fn new(ntdll_base: *mut c_void) -> Self {
        Self {
            export_rva: ExportRvaResolver::new(ntdll_base),
            hook_aware: HookAwareResolver::new(ntdll_base),
        }
    }
}

impl SsnResolver for DirectStealthResolver {
    fn resolve(&self, name_hash: u32) -> Option<Ssn> {
        // 1. ExportRva (FreshyCalls)
        if let Some(ssn) = self.export_rva.resolve(name_hash) {
            return Some(ssn);
        }

        // 2. HookAware (doğrudan temiz stub kontrolü)
        if let Some(ssn) = unsafe { self.hook_aware.resolve_clean(name_hash) } {
            return Some(ssn);
        }

        // 3. Halo's Gate / Tartarus' Gate (komşu tarama)
        if let Some(ssn) = unsafe { self.hook_aware.resolve_halos_tartarus(name_hash) } {
            return Some(ssn);
        }

        None
    }
}

/// ntdll export tablosunda hash ile eşleşen fonksiyon adresini döner.
///
/// # Safety
///
/// `ntdll_base` geçerli bir ntdll PE görüntüsü olmalıdır.
pub(crate) unsafe fn find_export_by_hash(
    ntdll_base: *mut c_void,
    target_hash: u32,
) -> Option<(*const u8, u32)> {
    if ntdll_base.is_null() {
        return None;
    }
    unsafe {
        let dos_header = ntdll_base as *const IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != 0x5A4D {
            return None;
        }

        let nt_headers =
            (ntdll_base as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        if (*nt_headers).signature != 0x00004550 {
            return None;
        }

        let export_dir_rva = (*nt_headers).optional_header.data_directory[0].virtual_address;
        if export_dir_rva == 0 {
            return None;
        }

        let export_dir =
            (ntdll_base as usize + export_dir_rva as usize) as *const IMAGE_EXPORT_DIRECTORY;

        let names_ptr =
            (ntdll_base as usize + (*export_dir).address_of_names as usize) as *const u32;
        let functions_ptr =
            (ntdll_base as usize + (*export_dir).address_of_functions as usize) as *const u32;
        let ordinals_ptr =
            (ntdll_base as usize + (*export_dir).address_of_name_ordinals as usize) as *const u16;

        let num_names = (*export_dir).number_of_names;

        for i in 0..num_names {
            let name_rva = *names_ptr.add(i as usize);
            let name_ptr = (ntdll_base as usize + name_rva as usize) as *const i8;

            let current_name = match std::ffi::CStr::from_ptr(name_ptr).to_str() {
                Ok(name) => name,
                Err(_) => continue,
            };

            let current_hash = utils::dbj2_hash(current_name);

            if current_hash == target_hash {
                let ordinal = *ordinals_ptr.add(i as usize);
                let func_rva = *functions_ptr.add(ordinal as usize);
                let func_addr = (ntdll_base as usize + func_rva as usize) as *const u8;
                return Some((func_addr, func_rva));
            }
        }

        None
    }
}
