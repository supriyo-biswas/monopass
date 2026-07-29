use std::ffi::{OsStr, c_void};
use std::io;
use std::ptr;
use std::time::Duration;

use axum::serve::Listener;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

pub(crate) struct NamedPipeListener {
    name: std::ffi::OsString,
    next: Option<NamedPipeServer>,
}

impl NamedPipeListener {
    pub(crate) fn bind(name: impl AsRef<OsStr>) -> io::Result<Self> {
        let name = name.as_ref().to_owned();
        let next = create_instance(&name, true)?;
        Ok(Self {
            name,
            next: Some(next),
        })
    }
}

impl Listener for NamedPipeListener {
    type Io = NamedPipeServer;
    type Addr = ();

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let Some(server) = self.next.take() else {
                match create_instance(&self.name, false) {
                    Ok(server) => {
                        self.next = Some(server);
                        continue;
                    }
                    Err(_) => {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                }
            };
            if server.connect().await.is_err() {
                self.next = None;
                continue;
            }

            loop {
                match create_instance(&self.name, false) {
                    Ok(next) => {
                        self.next = Some(next);
                        return (server, ());
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(())
    }
}

fn create_instance(name: &OsStr, first: bool) -> io::Result<NamedPipeServer> {
    let sid = crate::platform::windows::sid_string(&crate::platform::windows::current_user_sid()?)?;
    let sddl = format!("D:P(A;;GA;;;SY)(A;;GA;;;{sid})");
    let wide = crate::platform::windows::wide(&sddl);
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
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
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first)
        .reject_remote_clients(true)
        .max_instances(32);
    let result = unsafe {
        options.create_with_security_attributes_raw(
            name,
            (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
        )
    };
    unsafe { LocalFree(descriptor.cast()) };
    result
}
