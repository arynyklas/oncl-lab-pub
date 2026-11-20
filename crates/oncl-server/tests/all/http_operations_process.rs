use crate::server_support as support;

#[test]
fn standalone_binary_dispatches_typed_json_to_the_real_sdk() {
    let process = support::Process::start("");
    let runtime = support::runtime();
    let (status, bytes) = runtime.block_on(support::request(
        process.address,
        &process.token,
        "/v1/operations",
        br#"{"metadata":{"items":[{"id":"process","operation":{"kind":"hash","algorithm":"sha256","input":"doc"}}],"parts":[{"name":"doc","item_id":"process","role":"document"}]},"documents":{"doc":"abc"}}"#,
        &[("content-type", "application/json")],
        None,
    ));
    assert_eq!(status, 200);
    let result: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result["type"], "final");
    assert_eq!(result["status"], "completed");
    assert_eq!(result["results"][0]["item_id"], "process");
    assert_eq!(result["results"][0]["applied"], "NotApplied");
    assert_eq!(result["results"][0]["result"]["bytes_in"], 3);
    assert_eq!(
        result["results"][0]["result"]["digest"],
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    process.stop();
}

fn scratch_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        if kind.is_file() {
            files.push(entry.path());
        } else if kind.is_dir() {
            files.extend(scratch_files(&entry.path()));
        }
    }
    files
}
/// `ACCESS_ALLOWED_ACE_TYPE` (winnt.h); windows-sys keeps it behind an unneeded feature.
#[cfg(windows)]
const ACCESS_ALLOWED_ACE_TYPE: u32 = 0;
#[cfg(windows)]
fn assert_owner_only_file(path: &std::path::Path) {
    use std::ffi::c_void;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::{FALSE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
        GetSecurityDescriptorControl, GetTokenInformation, OWNER_SECURITY_INFORMATION,
        SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    struct Local(*mut c_void);
    impl Drop for Local {
        fn drop(&mut self) {
            // SAFETY: the pointer came from GetSecurityInfo, which allocates with LocalAlloc.
            unsafe { LocalFree(self.0) };
        }
    }

    // Current process token user SID.
    let mut token = std::ptr::null_mut();
    // SAFETY: the process pseudo-handle is valid and `token` is a writable out pointer.
    assert_ne!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) },
        FALSE,
        "OpenProcessToken failed: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: OpenProcessToken succeeded and returned one owned handle.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut length = 0;
    // SAFETY: size query with a null buffer of zero length.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut length,
        )
    };
    assert_ne!(length, 0, "TokenUser size query failed");
    let mut buffer = vec![0u64; (length as usize).div_ceil(8)];
    // SAFETY: u64 storage is 8-aligned and holds at least `length` bytes.
    assert_ne!(
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                buffer.as_mut_ptr().cast(),
                length,
                &mut length,
            )
        },
        FALSE,
        "GetTokenInformation failed: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: a successful TokenUser query starts with a TOKEN_USER; the SID points into `buffer`.
    let current = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };

    // READ_CONTROL only; share everything so concurrent holders do not interfere.
    let file = std::fs::OpenOptions::new()
        .access_mode(READ_CONTROL)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(path)
        .unwrap();
    let mut owner = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: the handle is a live file opened with READ_CONTROL; all out pointers are writable.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    assert_eq!(
        status,
        0,
        "ACL query of {} failed: error {status}",
        path.display()
    );
    let _descriptor = Local(descriptor);
    assert!(!owner.is_null() && !dacl.is_null());
    // SAFETY: both SIDs are valid and live while `descriptor` is held.
    assert_ne!(
        unsafe { EqualSid(owner, current) },
        FALSE,
        "owner is not the current user"
    );

    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: `descriptor` is a valid self-relative descriptor; out pointers are writable.
    assert_ne!(
        unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) },
        FALSE
    );
    assert!(
        control & SE_DACL_PROTECTED != 0,
        "actual child scratch file DACL must be protected"
    );

    // SAFETY: `dacl` is non-null and points into the live descriptor.
    let count = unsafe { (*dacl).AceCount };
    assert!(count > 0, "DACL must not be empty");
    for index in 0..u32::from(count) {
        let mut ace: *mut c_void = std::ptr::null_mut();
        // SAFETY: `index` is below AceCount; `ace` is a writable out pointer.
        assert_ne!(
            unsafe { GetAce(dacl, index, &mut ace) },
            FALSE,
            "GetAce({index}) failed: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: GetAce returned a pointer to an ACE, which starts with an ACE_HEADER.
        let kind = unsafe { (*ace.cast::<ACE_HEADER>()).AceType };
        assert_eq!(
            u32::from(kind),
            ACCESS_ALLOWED_ACE_TYPE,
            "non-allow ACE: type {kind}"
        );
        // SAFETY: an allowed ACE stores its SID inline starting at SidStart.
        let sid = unsafe { (&raw mut (*ace.cast::<ACCESS_ALLOWED_ACE>()).SidStart).cast() };
        // SAFETY: both SIDs are valid for the duration of the call.
        assert_ne!(
            unsafe { EqualSid(sid, current) },
            FALSE,
            "ACE for a foreign SID"
        );
    }
}
#[cfg(unix)]
fn assert_owner_only_file(path: &std::path::Path) {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.mode() & 0o077, 0);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(
        metadata.uid(),
        std::fs::metadata(path.parent().unwrap()).unwrap().uid()
    );
}

/// The SDK publication path hard-links the spool file; the published name must
/// keep the same protected, owner-only descriptor, not only the unpublished spool.
#[test]
fn published_hard_link_copy_keeps_the_protected_owner_only_descriptor() {
    use oncl_core::{Action, Engine, EngineServices, ExecutionGrant, OperationPolicy};
    use oncl_pki::resource::{OperationControl, ProcessingError, Progress, ResourceLimits};
    struct Allow;
    impl OperationControl for Allow {
        fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
            Ok(())
        }
    }
    let directory = support::sandbox();
    let spool = directory.path().join("spool");
    oncl_pki::private_fs::PrivateDirectory::create(&spool).unwrap();
    let published = directory.path().join("published");
    oncl_pki::private_fs::PrivateDirectory::create(&published).unwrap();
    let store = oncl_pki::io::TemporaryStore::new(&spool).unwrap();
    let engine = Engine::new(
        EngineServices::hash_only(ResourceLimits::default()).with_temporary_store(store.clone()),
    )
    .unwrap();
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Sign]),
            OperationPolicy::strict_online(),
            std::sync::Arc::new(Allow),
        )
        .unwrap();
    let mut staged = store.stage(ctx.resources()).unwrap();
    staged.write_chunk(b"published artifact bytes").unwrap();
    let spool_files = {
        let mut files = scratch_files(&spool);
        files.sort();
        files
    };
    assert_eq!(spool_files.len(), 1);
    assert_owner_only_file(&spool_files[0]);
    let destination = published.join("result.bin");
    staged.commit(&destination).unwrap();
    assert_eq!(
        std::fs::read(&destination).unwrap(),
        b"published artifact bytes"
    );
    // Same descriptor on the PUBLISHED name (Windows: protected DACL, owner SID).
    #[cfg(windows)]
    assert_owner_only_file(&destination);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(std::fs::metadata(&destination).unwrap().mode() & 0o077, 0);
    }
}

#[test]
fn standalone_multipart_uses_actual_random_private_scratch_and_cleans_it() {
    use std::{
        io::{Read, Write},
        time::{Duration, Instant},
    };
    // The upload stalls on purpose while the test inspects the staged file while the request
    // is still open: the slow-upload rules must not end the request and delete that file meanwhile.
    let process = support::Process::configured("127.0.0.1:0", |root| {
        format!(
            "scratch_directory = {}\nmax_in_flight = 1\nblocking_workers = 1\nqueue_capacity = 1\nupload_idle_timeout_ms = 120000\nupload_min_bytes_per_second = 0",
            support::toml_path(&root.join("scratch"))
        )
    });
    let scratch = process.directory.path().join("scratch");
    assert!(scratch_files(&scratch).is_empty());
    let mut stream = std::net::TcpStream::connect(process.address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let headers = format!(
        "POST /v1/operations HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: multipart/form-data; boundary=b\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        process.address,
        process.token.as_str()
    );
    stream.write_all(headers.as_bytes()).unwrap();
    let metadata = r#"{"items":[{"id":"process","operation":{"kind":"hash","algorithm":"sha256","input":"doc"}}],"parts":[{"name":"doc","item_id":"process","role":"document"}]}"#;
    let prefix = format!(
        "--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{metadata}\r\n--b\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"../../caller-selected.pdf\"\r\nContent-Type: application/pdf\r\n\r\nabc"
    );
    stream
        .write_all(format!("{:x}\r\n", prefix.len()).as_bytes())
        .unwrap();
    stream.write_all(prefix.as_bytes()).unwrap();
    stream.write_all(b"\r\n").unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let file = loop {
        let files = scratch_files(&scratch);
        if let Some(file) = files
            .into_iter()
            .find(|path| std::fs::metadata(path).unwrap().len() == 3)
        {
            break file;
        }
        assert!(
            Instant::now() < deadline,
            "actual input staging never became observable"
        );
        std::thread::park_timeout(Duration::from_millis(1));
    };
    assert_eq!(std::fs::read(&file).unwrap(), b"abc");
    let name = file.file_name().unwrap().to_str().unwrap();
    assert!(name.starts_with("oncl-"));
    assert_eq!(name.len(), 37);
    assert!(!name.contains("caller-selected"));
    assert_owner_only_file(&file);
    assert_eq!(
        support::runtime()
            .block_on(support::request(
                process.address,
                &process.token,
                "/health",
                b"",
                &[],
                None
            ))
            .0,
        200
    );
    let suffix = b"\r\n--b--\r\n";
    stream
        .write_all(format!("{:x}\r\n", suffix.len()).as_bytes())
        .unwrap();
    stream.write_all(suffix).unwrap();
    stream.write_all(b"\r\n0\r\n\r\n").unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let body = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap()
        + 4;
    let result: serde_json::Value = serde_json::from_slice(&response[body..]).unwrap();
    assert_eq!(result["type"], "final");
    assert_eq!(result["status"], "completed");
    assert_eq!(
        result["results"][0]["result"]["digest"],
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert!(scratch_files(&scratch).is_empty());
    assert!(
        !process
            .directory
            .path()
            .join("caller-selected.pdf")
            .exists()
    );
    let metadata = r#"{"items":[{"id":"secret","operation":{"kind":"hash","algorithm":"sha256","input":"key"}}],"parts":[{"name":"key","item_id":"secret","role":"secret"}]}"#;
    let secret = format!(
        "--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{metadata}\r\n--b\r\nContent-Disposition: form-data; name=\"key\"; filename=\"../private-key.pdf\"\r\nContent-Type: application/pdf\r\n\r\nCHILD-SECRET-MARKER-NEVER-SPOOL\r\n--b--\r\n"
    );
    let mut rejected = std::net::TcpStream::connect(process.address).unwrap();
    rejected
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let headers = format!(
        "POST /v1/operations HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: multipart/form-data; boundary=b\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        process.address,
        process.token.as_str(),
        secret.len()
    );
    rejected.write_all(headers.as_bytes()).unwrap();
    rejected.write_all(secret.as_bytes()).unwrap();
    let mut response = Vec::new();
    rejected.read_to_end(&mut response).unwrap();
    assert!(response.starts_with(b"HTTP/1.1 400"));
    assert!(!String::from_utf8_lossy(&response).contains("CHILD-SECRET-MARKER"));
    assert!(scratch_files(&scratch).is_empty());
    process.stop();
}
