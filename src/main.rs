use std::net::SocketAddr;
use std::process::{exit};
use std::time::Duration;
use std::{ffi::OsString, path::PathBuf};

use axum::{
    body::Body,
    routing::get,
    response::Json,
    Router,
};

mod flags {
    use super::*;
    xflags::xflags! {
        cmd HttpFileUploader {
            /// Bind and listen specified TCP socket
            optional -l,--listen addr : SocketAddr
            /// Optionally remove and bind this UNIX socket for listening incoming connections
            optional -u,--unix path: PathBuf
            /// Expect file descriptor 0 (or specified) to be pre-connected socket to serve only one connection
            optional --inetd
            /// Expect file descriptor 0 (or specified) to be pre-bound listening socket e.g. from systemd
            optional --accept
            /// File descriptor to use for --inetd or --accept modes instead of 0.
            optional --fd fd: u32
            /// Serve only one upload
            optional --once
            /// Dump contents of the file being uploaded to stdout. Implies --once
            optional -O,--stdout
            /// Save the file to specified location and overwrite it for each new upload (which may interleave)
            optional -o,--output path: PathBuf
            /// Execute specified program each time the upload starts, with URL as a sole command line parameter and file content as in stdin
            optional -p,--program path: PathBuf
            /// Execute command line (after --) each time the upload starts. URL is not propagated. Uploaded file content is in stdin.
            optional -c,--cmdline
        }
    }

    impl HttpFileUploader {
        pub fn validate_or_exit(&self) {
            if !has_exactly_one_true([self.listen.is_some() || self.unix.is_some(), self.inetd, self.accept])
            {
                eprintln!("Specify exactly one of --listen/--unix, --inetd or --accept");
                exit(1);
            }

            if !has_exactly_one_true([self.stdout, self.output.is_some(), self.program.is_some(), self.cmdline])
            {
                eprintln!("Specify exactly one of --stdout, --output, --program or --cmdline");
                exit(1);
            }

            if self.fd.is_some() {
                if !self.inetd && !self.accept {
                    eprintln!("--fd option is meaningless wiouth --inetd or --accept");
                    exit(1);
                }
            }
        }
    }
}


fn has_exactly_one_true(iter: impl IntoIterator<Item = bool>) -> bool {
    iter.into_iter().filter(|x|*x).count() == 1
}

async fn async_main(cmd: flags::HttpFileUploader) -> eyre::Result<()> {
    
    // `&'static str` becomes a `200 OK` with `content-type: text/plain; charset=utf-8`
    async fn plain_text() -> &'static str {
        "foo"
    }
    
    
    let app = Router::new()
        .route("/plain_text", get(plain_text));


    if let Some(la) = cmd.listen {
        let s = tokio::net::TcpListener::bind(la).await?;
        rt.spawn(async move {
            loop {
                match s.accept().await {
                    Ok((c, ca)) => {
                        eprintln!("Incoming connection from {}", ca);

                    }
                    Err(e) => {
                        eprintln!("Error accepting from TCP socket: {}", e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });
    } 

    Ok(())
}

fn main() -> eyre::Result<()> {
    let cmd = flags::HttpFileUploader::from_env_or_exit();
    cmd.validate_or_exit();

   
    let rt = tokio::runtime::Builder::new_current_thread().enable_io().enable_time().build()?;
    rt.block_on(async_main(cmd))?;

    Ok(())
}



