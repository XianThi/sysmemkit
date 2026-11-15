use sysmemkit::syscalls::resolver::{get_ntdll_base, ExportRvaResolver, HookAwareResolver};
use sysmemkit::syscalls::SsnResolver;
use sysmemkit::utils::dbj2_hash;

/// Canlı Windows ortamında ExportRvaResolver (FreshyCalls) ile HookAwareResolver (0xB8 tarama)
/// sonuçlarının hook'suz bir ntdll üzerinde birebir eşleştiğini doğrular.
#[test]
#[ignore]
fn test_ssn_consistency_live_ntdll() {
    let (ntdll_base, _) = unsafe { get_ntdll_base() };
    assert!(
        !ntdll_base.is_null(),
        "ntdll_base alınamadı (bu test yalnızca gerçek Windows x64 ortamında çalıştırılabilir)"
    );

    let (rva_resolver, hook_resolver) = unsafe {
        (
            ExportRvaResolver::new(ntdll_base),
            HookAwareResolver::new(ntdll_base),
        )
    };

    // sysmemkit bellek işlemlerinde kullanılan kritik Windows NT syscall'ları
    let test_functions = [
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtReadVirtualMemory",
        "NtWriteVirtualMemory",
        "NtQueryVirtualMemory",
        "NtOpenProcess",
        "NtClose",
    ];

    for func in test_functions {
        let hash = dbj2_hash(func);
        let ssn_rva = rva_resolver.resolve(hash);
        let ssn_hook = hook_resolver.resolve(hash);

        println!(
            "[*] Test: {:<26} -> RVA: {:?}, HookAware: {:?}",
            func, ssn_rva, ssn_hook
        );

        assert!(
            ssn_rva.is_some(),
            "ExportRvaResolver {} için SSN çözemedi",
            func
        );
        assert!(
            ssn_hook.is_some(),
            "HookAwareResolver {} için SSN çözemedi",
            func
        );

        assert_eq!(
            ssn_rva.unwrap().number,
            ssn_hook.unwrap().number,
            "{} için SSN uyuşmazlığı tespit edildi! RVA: {}, HookAware: {}",
            func,
            ssn_rva.unwrap().number,
            ssn_hook.unwrap().number
        );
    }
}


#[test]
fn test_extended_handle_struct_sizes() {
    use sysmemkit::include::def::{
        RUNTIME_FUNCTION, SYSTEM_HANDLE_INFORMATION_EX, SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX,
    };
    assert_eq!(
        std::mem::size_of::<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>(),
        40,
        "SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX 40 bayt olmalıdır (64-bit PID/HandleValue)"
    );
    assert_eq!(
        std::mem::size_of::<SYSTEM_HANDLE_INFORMATION_EX>(),
        16 + 40,
        "SYSTEM_HANDLE_INFORMATION_EX boyutu doğrulanmalı"
    );
    assert_eq!(
        std::mem::size_of::<RUNTIME_FUNCTION>(),
        12,
        "RUNTIME_FUNCTION 12 bayt olmalıdır"
    );
}

#[test]
#[ignore]
fn test_rop_invoker_pdata_gadgets_live() {
    use sysmemkit::syscalls::resolver::get_ntdll_base;
    #[cfg(feature = "rage")]
    use sysmemkit::syscalls::RopInvoker;

    #[allow(unused_variables)]
    let (ntdll_base, ntdll_size) = unsafe { get_ntdll_base() };
    assert!(!ntdll_base.is_null());

    #[cfg(feature = "rage")]
    {
        let rop = unsafe { RopInvoker::new(ntdll_base, ntdll_size) };
        assert!(rop.is_some(), "RopInvoker canlı ntdll üzerinde oluşturulabilmeli");
        let rop = rop.unwrap();
        println!("[*] Bulunan .pdata doğrulamalı gadget sayısı: {}", rop.gadgets.len());
        println!("[*] Bulunan meşru ret/unwind padding sayısı: {}", rop.paddings.len());
        assert!(!rop.paddings.is_empty(), "Meşru padding listesi boş olmamalı");
    }
}
