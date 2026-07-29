use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

pub(crate) fn create_private_dir_all(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    set_private_permissions(path)
}

pub(crate) fn create_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir(path)?;
    set_private_permissions(path)
}

#[cfg(unix)]
pub(crate) fn set_private_permissions(path: &Path) -> io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(windows)]
pub(crate) fn set_private_permissions(path: &Path) -> io::Result<()> {
    windows::apply_private_dacl(path)
}

pub(crate) fn open_private_new(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    configure_private_options(&mut options);
    let file = options.open(path)?;
    #[cfg(windows)]
    windows::apply_private_dacl(path)?;
    Ok(file)
}

pub(crate) fn open_private_truncate(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    configure_private_options(&mut options);
    let file = options.open(path)?;
    #[cfg(windows)]
    windows::apply_private_dacl(path)?;
    Ok(file)
}

pub(crate) fn configure_private_options(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    #[cfg(windows)]
    {
        options.share_mode(0);
    }
}

#[cfg(windows)]
pub(crate) mod windows {
    use std::ffi::OsStr;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::ptr;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetTokenInformation, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, SetFileSecurityW, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::UI::Shell::{
        FOLDERID_LocalAppData, KF_FLAG_CREATE, SHGetKnownFolderPath,
    };

    #[derive(Clone, PartialEq, Eq, Hash)]
    pub(crate) struct Sid(pub(crate) Vec<u8>);

    impl std::fmt::Debug for Sid {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("Sid([redacted])")
        }
    }

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    pub(crate) fn local_app_data_dir() -> io::Result<PathBuf> {
        let mut raw = ptr::null_mut();
        let result = unsafe {
            SHGetKnownFolderPath(
                &FOLDERID_LocalAppData,
                KF_FLAG_CREATE as u32,
                ptr::null_mut(),
                &mut raw,
            )
        };
        if result < 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        let len = unsafe {
            let mut len = 0usize;
            while *raw.add(len) != 0 {
                len += 1;
            }
            len
        };
        let path = PathBuf::from(String::from_utf16_lossy(unsafe {
            std::slice::from_raw_parts(raw, len)
        }));
        unsafe { CoTaskMemFree(raw.cast()) };
        Ok(path)
    }

    pub(crate) fn current_user_sid() -> io::Result<Sid> {
        let mut token = ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        token_user_sid(OwnedHandle(token))
    }

    fn token_user_sid(token: OwnedHandle) -> io::Result<Sid> {
        let mut required = 0u32;
        unsafe {
            GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut required);
        }
        if required == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buffer = vec![0u8; required as usize];
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
        copy_sid(user.User.Sid)
    }

    pub(crate) fn sid_string(sid: &Sid) -> io::Result<String> {
        let mut raw = ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(sid.0.as_ptr().cast_mut().cast(), &mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let len = unsafe {
            let mut len = 0usize;
            while *raw.add(len) != 0 {
                len += 1;
            }
            len
        };
        let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(raw, len) });
        unsafe { LocalFree(raw.cast()) };
        Ok(value)
    }

    fn copy_sid(sid: PSID) -> io::Result<Sid> {
        use windows_sys::Win32::Security::{CopySid, GetLengthSid, IsValidSid};

        if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Windows SID",
            ));
        }
        let len = unsafe { GetLengthSid(sid) };
        let mut bytes = vec![0u8; len as usize];
        if unsafe { CopySid(len, bytes.as_mut_ptr().cast(), sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Sid(bytes))
    }

    pub(crate) fn apply_private_dacl(path: &Path) -> io::Result<()> {
        let sid = sid_string(&current_user_sid()?)?;
        let sddl = format!("O:{sid}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{sid})");
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let wide = wide(&sddl);
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }

        let mut path = path.as_os_str().encode_wide().collect::<Vec<_>>();
        path.push(0);
        let result = unsafe {
            SetFileSecurityW(
                path.as_ptr(),
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                descriptor,
            )
        };
        unsafe { LocalFree(descriptor.cast()) };
        if result != 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(crate) fn wide(value: &str) -> Vec<u16> {
        OsStr::new(value).encode_wide().chain(Some(0)).collect()
    }
}
