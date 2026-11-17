use crate::syscalls::invoker::do_syscall;
use crate::syscalls::resolver::{get_ntdll_base, get_ssn_by_hash};
use crate::utils::dbj2_hash;
use std::ffi::c_void;

/// "48 8B ? 05" biçimindeki pattern'i byte maskesine çevirir.
/// `?` / `??` joker, diğerleri iki haneli hex olmalı.
/// Boş veya geçersiz pattern -> `None` (panic yok).
pub fn parse_pattern(pattern: &str) -> Option<Vec<Option<u8>>> {
    let mut mask = Vec::new();
    for token in pattern.split_whitespace() {
        if token == "?" || token == "??" {
            mask.push(None);
        } else {
            mask.push(Some(u8::from_str_radix(token, 16).ok()?));
        }
    }

    if mask.is_empty() { None } else { Some(mask) }
}

/// Bir byte dilimi içinde pattern'i arar (güvenli, sınır kontrollü).
/// Dönüş: eşleşmenin dilim içindeki ofseti.
pub fn find_pattern_in(haystack: &[u8], pattern: &[Option<u8>]) -> Option<usize> {
    if pattern.is_empty() || haystack.len() < pattern.len() {
        return None;
    }

    let last_start = haystack.len() - pattern.len();
    (0..=last_start).find(|&i| {
        pattern.iter().enumerate().all(|(j, expected)| match expected {
            Some(b) => haystack[i + j] == *b,
            None => true,
        })
    })
}

/// Modül içinde `0x3200014` (Discord overlay SharedMemoryInfo magic) arar.
pub unsafe fn find_hash_map_pattern(
    process_handle: *mut c_void,
    module_base: usize,
    module_size: usize,
) -> Option<usize> {
    const MAGIC: u32 = 0x3200014;
    const CHUNK: usize = 0x1000;

    if process_handle.is_null() || module_base == 0 || module_size < 4 {
        return None;
    }

    // İlk 16 MB taranır.
    let scan_size = module_size.min(0x1000_0000);

    unsafe {
        let (ntdll, _ntdll_size) = get_ntdll_base();
        if ntdll.is_null() {
            return None;
        }
        const HASH_NT_READ: u32 = dbj2_hash("NtReadVirtualMemory");
        let ssn_read = get_ssn_by_hash(ntdll, HASH_NT_READ)?;

        let mut buf = vec![0u8; CHUNK];
        let mut br: usize = 0;

        for offset in (0..scan_size).step_by(CHUNK) {
            let addr = module_base + offset;
            let mut args = [
                process_handle as usize,
                addr,
                buf.as_mut_ptr() as usize,
                CHUNK,
                &mut br as *mut usize as usize,
            ];

            let status = do_syscall(ssn_read, args.as_mut_ptr());
            if status != 0 || br < 4 {
                // Okunamayan sayfa: sıradaki chunk'a geç.
                br = 0;
                continue;
            }

            let readable = br.min(CHUNK);
            for i in 0..=(readable - 4) {
                let magic = u32::from_le_bytes([
                    buf[i],
                    buf[i + 1],
                    buf[i + 2],
                    buf[i + 3],
                ]);
                if magic == MAGIC {
                    return Some(addr + i);
                }
            }

            br = 0;
        }
    }

    None
}

/// Uzak süreç belleğinde pattern arar (tek sonuç).
///
/// # Safety
///
/// `process_handle` `VM_READ` yetkisiyle açılmış olmalı ve `start..start+size` hedef süreçte
/// okunabilir olmalıdır. Okunamayan sayfalar tarama dışında kalır.
pub unsafe fn pattern_scan(
    process_handle: *mut c_void,
    start: usize,
    size: usize,
    pattern: &str,
) -> Option<usize> {
    if process_handle.is_null() || start == 0 || size == 0 {
        return None;
    }

    let pattern_bytes = parse_pattern(pattern)?;
    if size < pattern_bytes.len() {
        return None;
    }

    unsafe {
        let (ntdll, _ntdll_size) = get_ntdll_base();
        if ntdll.is_null() {
            return None;
        }
        const HASH_NT_READ: u32 = dbj2_hash("NtReadVirtualMemory");
        let ssn_read = get_ssn_by_hash(ntdll, HASH_NT_READ)?;

        // DİKKAT: uzak okuma boyutu çağıranın istediği `size` olmalı.
        let mut buffer = vec![0u8; size];
        let mut br: usize = 0;
        let mut args = [
            process_handle as usize,
            start,
            buffer.as_mut_ptr() as usize,
            size,
            &mut br as *mut usize as usize,
        ];

        let status = do_syscall(ssn_read, args.as_mut_ptr());
        if status != 0 || br == 0 {
            return None;
        }

        let readable = br.min(size);
        find_pattern_in(&buffer[..readable], &pattern_bytes).map(|i| start + i)
    }
}

/// Kendi adres uzayımızda pattern arar (tek sonuç).
pub unsafe fn pattern_scan_local(start: usize, size: usize, pattern: &str) -> Option<usize> {
    if start == 0 || size == 0 {
        return None;
    }

    let pattern_bytes = parse_pattern(pattern)?;
    if size < pattern_bytes.len() {
        return None;
    }

    let mut buffer = vec![0u8; size];
    unsafe { std::ptr::copy_nonoverlapping(start as *const u8, buffer.as_mut_ptr(), size) };

    find_pattern_in(&buffer, &pattern_bytes).map(|i| start + i)
}

/// Kendi adres uzayımızda tüm eşleşmeleri döndürür.
///
/// # Safety
///
/// `start..start+size` bu süreçte eşlenmiş ve okunabilir olmalıdır; aralık dışına taşan erişim
/// tanımsız davranıştır.
pub unsafe fn pattern_scan_all_local(start: usize, size: usize, pattern: &str) -> Vec<usize> {
    let mut matches = Vec::new();
    if start == 0 || size == 0 {
        return matches;
    }

    let pattern_bytes = match parse_pattern(pattern) {
        Some(p) => p,
        None => return matches,
    };

    let pattern_len = pattern_bytes.len();
    if size < pattern_len {
        return matches;
    }

    for i in 0..=(size - pattern_len) {
        let mut found = true;
        for (j, expected) in pattern_bytes.iter().enumerate() {
            if let Some(b) = expected {
                let current = unsafe { *((start + i + j) as *const u8) };
                if current != *b {
                    found = false;
                    break;
                }
            }
        }

        if found {
            matches.push(start + i);
        }
    }

    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pattern_handles_jokers_and_hex() {
        let p = parse_pattern("48 8B ? 05").unwrap();
        assert_eq!(p, vec![Some(0x48), Some(0x8B), None, Some(0x05)]);

        let p2 = parse_pattern("?? 0f").unwrap();
        assert_eq!(p2, vec![None, Some(0x0F)]);
    }

    #[test]
    fn parse_pattern_rejects_garbage() {
        assert!(parse_pattern("").is_none());
        assert!(parse_pattern("   ").is_none());
        assert!(parse_pattern("GG").is_none());
        assert!(parse_pattern("1234").is_none());
        assert!(parse_pattern("48 8B ZZ").is_none());
    }

    #[test]
    fn find_pattern_in_bounds() {
        let hay = [0x00u8, 0x48, 0x8B, 0x11, 0xC3];
        let pat = parse_pattern("48 8B ? C3").unwrap();
        assert_eq!(find_pattern_in(&hay, &pat), Some(1));

        // Pattern buffer'dan uzun -> panik yok, None.
        let long = parse_pattern("48 8B 11 C3 90 90 90 90 90").unwrap();
        assert_eq!(find_pattern_in(&hay, &long), None);

        // Bulunamayan pattern.
        let missing = parse_pattern("DE AD BE EF").unwrap();
        assert_eq!(find_pattern_in(&hay, &missing), None);
    }

    #[test]
    fn find_pattern_in_exact_length_match() {
        let hay = [0xAAu8, 0xBB];
        let pat = parse_pattern("AA BB").unwrap();
        assert_eq!(find_pattern_in(&hay, &pat), Some(0));
    }

    #[test]
    fn pattern_scan_all_local_finds_every_hit() {
        let buf: [u8; 8] = [0x90, 0xC3, 0x90, 0xC3, 0x90, 0x90, 0x90, 0xC3];
        let hits = unsafe { pattern_scan_all_local(buf.as_ptr() as usize, buf.len(), "C3") };
        assert_eq!(hits.len(), 3);
        assert_eq!(hits[0], buf.as_ptr() as usize + 1);

        // Sınır durumları panik üretmemeli.
        assert!(unsafe { pattern_scan_all_local(buf.as_ptr() as usize, 1, "C3 C3") }.is_empty());
        assert!(unsafe { pattern_scan_all_local(buf.as_ptr() as usize, buf.len(), "") }.is_empty());
    }

    #[test]
    fn pattern_scan_local_returns_absolute_address() {
        let buf: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let base = buf.as_ptr() as usize;
        let hit = unsafe { pattern_scan_local(base, buf.len(), "33 44") };
        assert_eq!(hit, Some(base + 2));

        let none = unsafe { pattern_scan_local(base, buf.len(), "AA") };
        assert_eq!(none, None);
    }
}
