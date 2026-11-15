/// DJB2 (xor'suz) — ntdll export adlarını hash'lemek için kullanılır.
pub const fn dbj2_hash(s: &str) -> u32 {
    let mut hash: u32 = 5381;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        hash = (hash << 5).wrapping_add(hash).wrapping_add(bytes[i] as u32);
        i += 1;
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::dbj2_hash;

    #[test]
    fn dj2b_empty_is_seed() {
        assert_eq!(dbj2_hash(""), 5381);
    }

    #[test]
    fn dbj2_known_values() {
        // 5381 * 33 + 'a'(97)
        assert_eq!(dbj2_hash("a"), 177_670);
        assert_eq!(dbj2_hash("a"), (5381u32.wrapping_mul(33)).wrapping_add(97));
    }

    #[test]
    fn dbj2_is_ascii_case_sensitive() {
        assert_ne!(dbj2_hash("NtReadVirtualMemory"), dbj2_hash("ntreadvirtualmemory"));
    }

    #[test]
    fn dbj2_usable_in_const_context() {
        const HASH: u32 = dbj2_hash("NtClose");
        assert_eq!(HASH, dbj2_hash("NtClose"));
    }
}
