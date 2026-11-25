//! Windows NTFS DACL hardening for vault directories and `master.key` files.
//!
//! Uses Win32 `advapi32` / `kernel32` FFI directly so both desktop and headless
//! (`--no-default-features`) Windows builds enforce owner-only permissions
//! without extra crates or spawning `icacls.exe`.

use anyhow::{Context, Result, bail};
use std::{
    ffi::{OsStr, c_void},
    os::windows::ffi::OsStrExt,
    path::Path,
    ptr,
    sync::OnceLock,
};

const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_USER_INFO_CLASS: u32 = 1;
const SDDL_REVISION_1: u32 = 1;
const SE_FILE_OBJECT: u32 = 1;
const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;

const ERROR_SUCCESS: u32 = 0;
const ERROR_INVALID_FUNCTION: u32 = 1;
const ERROR_NOT_SUPPORTED: u32 = 50;

#[repr(C)]
struct SidAndAttributes {
    sid: *mut c_void,
    attributes: u32,
}

#[repr(C)]
struct TokenUser {
    user: SidAndAttributes,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> *mut c_void;
    fn CloseHandle(object: *mut c_void) -> i32;
    fn LocalFree(mem: *mut c_void) -> *mut c_void;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(
        process_handle: *mut c_void,
        desired_access: u32,
        token_handle: *mut *mut c_void,
    ) -> i32;
    fn GetTokenInformation(
        token_handle: *mut c_void,
        token_information_class: u32,
        token_information: *mut c_void,
        token_information_length: u32,
        return_length: *mut u32,
    ) -> i32;
    fn ConvertSidToStringSidW(sid: *mut c_void, string_sid: *mut *mut u16) -> i32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string_security_descriptor: *const u16,
        string_sd_revision: u32,
        security_descriptor: *mut *mut c_void,
        security_descriptor_size: *mut u32,
    ) -> i32;
    fn GetSecurityDescriptorDacl(
        security_descriptor: *mut c_void,
        dacl_present: *mut i32,
        dacl: *mut *mut c_void,
        dacl_defaulted: *mut i32,
    ) -> i32;
    fn SetNamedSecurityInfoW(
        object_name: *mut u16,
        object_type: u32,
        security_info: u32,
        owner: *mut c_void,
        group: *mut c_void,
        dacl: *mut c_void,
        sacl: *mut c_void,
    ) -> u32;
    #[cfg(test)]
    fn GetNamedSecurityInfoW(
        object_name: *const u16,
        object_type: u32,
        security_info: u32,
        owner: *mut *mut c_void,
        group: *mut *mut c_void,
        dacl: *mut *mut c_void,
        sacl: *mut *mut c_void,
        security_descriptor: *mut *mut c_void,
    ) -> u32;
    #[cfg(test)]
    fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
        security_descriptor: *mut c_void,
        requested_string_sd_revision: u32,
        security_information: u32,
        string_security_descriptor: *mut *mut u16,
        string_security_descriptor_len: *mut u32,
    ) -> i32;
}

struct OwnedHandle(*mut c_void);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

struct LocalMem(*mut c_void);

impl Drop for LocalMem {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

fn to_wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

unsafe fn wide_ptr_to_string(ptr: *const u16) -> String {
    let mut len = 0_usize;
    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
    }
}

/// Returns the current process owner's SID string (e.g. `S-1-5-21-...`), cached
/// for the lifetime of the process.
pub(super) fn current_user_sid() -> Result<&'static str> {
    static SID: OnceLock<std::result::Result<String, String>> = OnceLock::new();
    match SID.get_or_init(|| query_current_user_sid().map_err(|e| format!("{e:#}"))) {
        Ok(sid) => Ok(sid.as_str()),
        Err(message) => bail!("{message}"),
    }
}

fn query_current_user_sid() -> Result<String> {
    let mut token_raw = ptr::null_mut();
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_raw) };
    if ok == 0 || token_raw.is_null() {
        return Err(std::io::Error::last_os_error()).context("Unable to open process token");
    }
    let _token = OwnedHandle(token_raw);

    let mut needed = 0_u32;
    unsafe {
        GetTokenInformation(
            token_raw,
            TOKEN_USER_INFO_CLASS,
            ptr::null_mut(),
            0,
            &mut needed,
        );
    }
    if needed == 0 {
        return Err(std::io::Error::last_os_error()).context("Unable to size TokenUser buffer");
    }
    let words = (needed as usize).div_ceil(std::mem::size_of::<usize>());
    let mut buffer = vec![0_usize; words];
    let ok = unsafe {
        GetTokenInformation(
            token_raw,
            TOKEN_USER_INFO_CLASS,
            buffer.as_mut_ptr().cast(),
            (words * std::mem::size_of::<usize>()) as u32,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error()).context("Unable to read TokenUser");
    }

    let token_user = unsafe { &*(buffer.as_ptr().cast::<TokenUser>()) };
    if token_user.user.sid.is_null() {
        bail!("Process token did not contain a user SID");
    }

    let mut sid_wide: *mut u16 = ptr::null_mut();
    let ok = unsafe { ConvertSidToStringSidW(token_user.user.sid, &mut sid_wide) };
    if ok == 0 || sid_wide.is_null() {
        return Err(std::io::Error::last_os_error()).context("Unable to format user SID");
    }
    let _sid_mem = LocalMem(sid_wide.cast());
    Ok(unsafe { wide_ptr_to_string(sid_wide) })
}

/// Replaces the file or directory's DACL with a protected (`D:P`) ACL that
/// grants full access only to the current user and `SYSTEM`, stripping any
/// permissions inherited from a shared parent directory.
///
/// Filesystems without NTFS ACL support (such as FAT32/exFAT removable drives)
/// return `ERROR_INVALID_FUNCTION` or `ERROR_NOT_SUPPORTED` and are treated as
/// a best-effort no-op.
pub(super) fn harden_owner_only(path: &Path, is_dir: bool) -> Result<()> {
    let owner_sid = current_user_sid()?;
    let sddl = if is_dir {
        format!("D:P(A;OICI;FA;;;{owner_sid})(A;OICI;FA;;;SY)")
    } else {
        format!("D:P(A;;FA;;;{owner_sid})(A;;FA;;;SY)")
    };
    let sddl_wide = to_wide_null(OsStr::new(&sddl));
    let mut sd_raw = ptr::null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_wide.as_ptr(),
            SDDL_REVISION_1,
            &mut sd_raw,
            ptr::null_mut(),
        )
    };
    if ok == 0 || sd_raw.is_null() {
        return Err(std::io::Error::last_os_error())
            .context("Unable to build Windows owner-only security descriptor");
    }
    let _sd = LocalMem(sd_raw);

    let mut dacl_present = 0_i32;
    let mut dacl = ptr::null_mut();
    let mut dacl_defaulted = 0_i32;
    let ok = unsafe {
        GetSecurityDescriptorDacl(sd_raw, &mut dacl_present, &mut dacl, &mut dacl_defaulted)
    };
    if ok == 0 || dacl_present == 0 || dacl.is_null() {
        return Err(std::io::Error::last_os_error())
            .context("Unable to extract DACL from Windows security descriptor");
    }

    let mut path_wide = to_wide_null(path.as_os_str());
    let status = unsafe {
        SetNamedSecurityInfoW(
            path_wide.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null_mut(),
        )
    };
    match status {
        ERROR_SUCCESS | ERROR_INVALID_FUNCTION | ERROR_NOT_SUPPORTED => Ok(()),
        code => Err(std::io::Error::from_raw_os_error(code as i32))
            .with_context(|| format!("Unable to tighten Windows ACL on {}", path.display())),
    }
}

#[cfg(test)]
pub(super) fn read_dacl_sddl(path: &Path) -> Result<String> {
    let path_wide = to_wide_null(path.as_os_str());
    let mut sd_raw = ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut sd_raw,
        )
    };
    if status != ERROR_SUCCESS || sd_raw.is_null() {
        return Err(std::io::Error::from_raw_os_error(status as i32))
            .with_context(|| format!("Unable to read Windows ACL on {}", path.display()));
    }
    let _sd = LocalMem(sd_raw);

    let mut sddl_wide: *mut u16 = ptr::null_mut();
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd_raw,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut sddl_wide,
            ptr::null_mut(),
        )
    };
    if ok == 0 || sddl_wide.is_null() {
        return Err(std::io::Error::last_os_error())
            .context("Unable to format Windows DACL as SDDL");
    }
    let _sddl_mem = LocalMem(sddl_wide.cast());
    Ok(unsafe { wide_ptr_to_string(sddl_wide) })
}
