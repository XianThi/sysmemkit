pub mod invoker;
pub mod resolver;

/// Sistem çağrısı numarası (SSN) ve çağrı stub'ı adresi.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ssn {
    /// Sistem çağrısı numarası (System Service Number)
    pub number: u16,
    /// ntdll içindeki syscall stub adresi (`0F 05 C3`). Faz 3'te indirect syscall için kullanılır.
    pub stub: usize,
}

/// ntdll export tablosu veya PE başlıklarından SSN çözen bileşenler için arayüz.
pub trait SsnResolver: Send + Sync {
    /// Fonksiyon adı hash'inden SSN ve stub adresini çözer.
    fn resolve(&self, name_hash: u32) -> Option<Ssn>;
}

pub use invoker::{
    do_syscall, find_all_syscall_stub_pattern, find_syscall_stub_pattern, indirect_syscall,
    indirect_syscall_trampoline, DirectInvoker, IndirectInvoker, RandomizerInvoker, SyscallInvoker,
};
#[cfg(feature = "rage")]
pub use invoker::RopInvoker;
pub use resolver::{
    extract_clean_ssn, find_clean_neighbor_syscall, find_syscall_in_stub, get_ntdll_base,
    get_ssn_by_hash, get_ssn_stub_by_hash, get_syscall_number, get_text_section_bounds,
    halos_tartarus_walk, halos_tartarus_walk_with_stub, is_stub_hooked, DirectStealthResolver,
    ExportByteResolver, ExportRvaResolver, HookAwareResolver,
};


#[cfg(test)]
mod tests {
    #[test]
    fn test_halo_and_tartarus_gate_simulation() {
        use crate::syscalls::resolver::{extract_clean_ssn, halos_tartarus_walk, is_stub_hooked};

        // 4 adet 32-baytlık ardışık stub simülasyonu (toplam 128 bayt)
        // Stub 0: offset 0x00, SSN 0x18, temiz (4C 8B D1 B8 18 00 00 00 ... 0F 05 C3)
        // Stub 1: offset 0x20, SSN 0x19, HOOKED (offset 0: E9 00 11 22 33 ...)
        // Stub 2: offset 0x40, SSN 0x1A, HOOKED (offset 3: 4C 8B D1 E9 00 11 22 33 ...)
        // Stub 3: offset 0x60, SSN 0x1B, temiz (4C 8B D1 B8 1B 00 00 00 ... 0F 05 C3)
        let mut buffer = [0x90u8; 128];

        // Stub 0 hazırla
        buffer[0] = 0x4C; buffer[1] = 0x8B; buffer[2] = 0xD1; buffer[3] = 0xB8;
        buffer[4] = 0x18; buffer[5] = 0x00; // SSN = 0x18

        // Stub 1 hazırla (Halo's Gate senaryosu: E9 at offset 0)
        buffer[32] = 0xE9; buffer[33] = 0x50; buffer[34] = 0x10; buffer[35] = 0x00; buffer[36] = 0x00;

        // Stub 2 hazırla (Tartarus' Gate senaryosu: E9 at offset 3)
        buffer[64] = 0x4C; buffer[65] = 0x8B; buffer[66] = 0xD1;
        buffer[67] = 0xE9; buffer[68] = 0x20; buffer[69] = 0x20; buffer[70] = 0x00; buffer[71] = 0x00;

        // Stub 3 hazırla
        buffer[96] = 0x4C; buffer[97] = 0x8B; buffer[98] = 0xD1; buffer[99] = 0xB8;
        buffer[100] = 0x1B; buffer[101] = 0x00; // SSN = 0x1B

        let base_ptr = buffer.as_ptr();
        let text_start = base_ptr as usize;
        let text_end = text_start + buffer.len();

        unsafe {
            // Stub 0 temiz olmalı
            assert!(!is_stub_hooked(base_ptr));
            assert_eq!(extract_clean_ssn(base_ptr), Some(0x18));

            // Stub 1 hook'lu olmalı (Halo's Gate)
            let stub1_ptr = base_ptr.add(32);
            assert!(is_stub_hooked(stub1_ptr));
            assert_eq!(extract_clean_ssn(stub1_ptr), None);

            // Stub 2 hook'lu olmalı (Tartarus' Gate)
            let stub2_ptr = base_ptr.add(64);
            assert!(is_stub_hooked(stub2_ptr));
            assert_eq!(extract_clean_ssn(stub2_ptr), None);

            // Stub 3 temiz olmalı
            let stub3_ptr = base_ptr.add(96);
            assert!(!is_stub_hooked(stub3_ptr));
            assert_eq!(extract_clean_ssn(stub3_ptr), Some(0x1B));

            // Halo's Gate ile Stub 1'i çöz:
            // Stub 0 komşusu (-1): 0x18 + 1 = 0x19
            let ssn1 = halos_tartarus_walk(stub1_ptr as usize, text_start, text_end);
            assert_eq!(ssn1, Some(0x19));

            // Tartarus' Gate ile Stub 2'yi çöz:
            // Stub 3 komşusu (+1): 0x1B - 1 = 0x1A
            let ssn2 = halos_tartarus_walk(stub2_ptr as usize, text_start, text_end);
            assert_eq!(ssn2, Some(0x1A));
        }
    }

    use super::*;

    #[test]
    fn test_ssn_struct() {
        let ssn = Ssn {
            number: 0x18,
            stub: 0x7FFF0000,
        };
        assert_eq!(ssn.number, 0x18);
        assert_eq!(ssn.stub, 0x7FFF0000);
    }

    #[test]
    fn test_resolvers_null_base() {
        unsafe {
            let export_resolver = resolver::ExportByteResolver::new(std::ptr::null_mut());
            assert!(export_resolver.resolve(0x1234).is_none());

            let hook_resolver = resolver::HookAwareResolver::new(std::ptr::null_mut());
            assert!(hook_resolver.resolve(0x1234).is_none());

            let rva_resolver = resolver::ExportRvaResolver::new(std::ptr::null_mut());
            assert!(rva_resolver.resolve(0x1234).is_none());

            let stealth_resolver = resolver::DirectStealthResolver::new(std::ptr::null_mut());
            assert!(stealth_resolver.resolve(0x1234).is_none());
        }
    }
    #[test]
    fn test_find_syscall_in_stub() {
        use crate::syscalls::resolver::find_syscall_in_stub;
        let mut stub = [0x90u8; 32];
        stub[0] = 0x4C; stub[1] = 0x8B; stub[2] = 0xD1; // mov r10, rcx
        stub[3] = 0xB8; stub[4] = 0x18; stub[5] = 0x00; // mov eax, 0x18
        stub[18] = 0x0F; stub[19] = 0x05; // syscall
        stub[20] = 0xC3; // ret

        unsafe {
            let sc = find_syscall_in_stub(stub.as_ptr());
            assert_eq!(sc, Some(stub.as_ptr().add(18) as usize));
        }
    }

    #[test]
    fn test_invoker_structures() {
        let direct = DirectInvoker;
        assert_eq!(direct.name(), "Direct");

        let indirect = IndirectInvoker { fallback_stub: 0x1234 };
        assert_eq!(indirect.name(), "Indirect");

        let randomizer = RandomizerInvoker {
            stubs: vec![0x1234, 0x5678],
            fallback_stub: 0x1234,
        };
        assert_eq!(randomizer.name(), "Randomizer");
    }
}
