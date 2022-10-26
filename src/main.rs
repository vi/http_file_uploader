use std::ffi::OsStr;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::process::exit;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use std::{ffi::OsString, path::PathBuf};

use anyhow::Context as _;
use axum::body::Bytes;
use axum::error_handling::HandleErrorLayer;
use axum::extract::multipart::Field;
use axum::extract::{Multipart, RequestParts};
use axum::handler::Handler;
use axum::response::{IntoResponse, Response};
use axum::Router;
use axum::{BoxError, Extension};
use futures_util::{Stream, StreamExt, TryStreamExt};
use hyper::header::CONTENT_TYPE;
use hyper::{Body, Request, StatusCode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::{Child, Command};
use tower::buffer::BufferLayer;
use tower::limit::ConcurrencyLimitLayer;
use tower::ServiceBuilder;

use crate::flags::{CmdSink, CmdSinkProg};

mod flags {
    use std::path::Path;

    use super::*;
    xflags::xflags! {
        src "./src/main.rs"
        /// Special web server to allow shell scripts and other simple UNIX-ey programs to handle multipart/form-data HTTP  file uploads
        cmd http-file-uploader {
            /// Bind and listen specified TCP socket
            optional -l,--listen addr : SocketAddr
            /// Optionally remove and bind this UNIX socket for listening incoming connections
            optional -u,--unix path: PathBuf
            /// Read from HTTP request from stdin and write HTTP response to stdout
            optional --inetd
            /// Expect file descriptor 0 (or specified) to be pre-bound listening TCP socket e.g. from systemd's socket activation
            /// You may want to specify `--fd 3` for systemd
            optional --accept-tcp
            /// Expect file descriptor 0 (or specified) to be pre-bound listening UNIX socket e.g. from systemd's socket activation
            /// You may want to specify `--fd 3` for systemd
            optional --accept-unix
            /// File descriptor to use for --inetd or --accept-... modes instead of 0.
            optional --fd fd: i32
            /// Serve only one successful upload, then exit.
            /// Failed child process executions are not considered as unsuccessful uploads for `--once` purposes, only invalid HTTP requests.
            /// E.g. trying to write to /dev/full does exit with --once, but failure to open --output file does not.
            optional --once
            /// Dump contents of the file being uploaded to stdout.
            optional -O,--stdout
            /// Save the file to specified location and overwrite it for each new upload
            optional -o,--output path: PathBuf
            /// Execute specified program each time the upload starts, without CLI parameters by default and file content as in stdin
            /// On UNIX, SIGINT is sent to the process if upload is terminated prematurely
            optional -p,--program path: PathBuf
            /// Execute command line (after --) each time the upload starts. URL is not propagated. Uploaded file content is in stdin.
            /// On UNIX, SIGINT is sent to the process if upload is terminated prematurely
            optional -c,--cmdline
            /// Command line array for --cmdline option
            repeated argv: OsString
            /// Restrict multipart field to specified name instead of taking first encountred field.
            optional -n,--name field_name: String
            /// Require a file to be uploaded, otherwise failing the request.
            optional -r,--require-upload
            /// Allow multiple uploads simultaneously without any limit
            optional -L,--parallelism
            /// Limit number of upload-serving processes running in parallel.
            /// You may want to also use -Q option
            optional -j,--parallelism-limit limit: usize
            /// Number of queued waiting requests before starting failing them with 429. Default is no queue.
            /// Note that single TCP connection can issue multiple requests in parallel, filling up the queue.
            optional -Q,--queue len: usize
            /// Buffer child process output to return it to HTTP client as text/plain
            optional -B,--buffer-child-stdout
            /// Remove --output file if the upload was interrupted
            optional --remove-incomplete
            /// Move --output's file to new path after the upload is fully completed
            optional --rename-complete path: PathBuf
            /// Append request URL as additional command line parameter
            optional -U, --url
            /// Append request URL as additional command line parameter, base64-encoded
            optional --url-base64
            /// Do not announce new connections
            optional -q, --quiet
            /// Allow plain, non-multipart/form-data requests (and stream body chunks instead of form field's chunks)
            optional -P,--allow-nonmultipart
            /// Don't try to decode multipart/form-data content, just stream request body as is always.
            optional --no-multipart
            /// Append HTTP request method to the command line parameters (before --url if specified)
            optional -M,--method
        }
    }
    // generated start
    // The following code is generated by `xflags` macro.
    // Run `env UPDATE_XFLAGS=1 cargo build` to regenerate.
    #[derive(Debug)]
    pub struct HttpFileUploader {
        pub argv: Vec<OsString>,

        pub listen: Option<SocketAddr>,
        pub unix: Option<PathBuf>,
        pub inetd: bool,
        pub accept_tcp: bool,
        pub accept_unix: bool,
        pub fd: Option<i32>,
        pub once: bool,
        pub stdout: bool,
        pub output: Option<PathBuf>,
        pub program: Option<PathBuf>,
        pub cmdline: bool,
        pub name: Option<String>,
        pub require_upload: bool,
        pub parallelism: bool,
        pub parallelism_limit: Option<usize>,
        pub queue: Option<usize>,
        pub buffer_child_stdout: bool,
        pub remove_incomplete: bool,
        pub rename_complete: Option<PathBuf>,
        pub url: bool,
        pub url_base64: bool,
        pub quiet: bool,
        pub allow_nonmultipart: bool,
        pub no_multipart: bool,
        pub method: bool,
    }

    impl HttpFileUploader {
        #[allow(dead_code)]
        pub fn from_env_or_exit() -> Self {
            Self::from_env_or_exit_()
        }

        #[allow(dead_code)]
        pub fn from_env() -> xflags::Result<Self> {
            Self::from_env_()
        }

        #[allow(dead_code)]
        pub fn from_vec(args: Vec<std::ffi::OsString>) -> xflags::Result<Self> {
            Self::from_vec_(args)
        }
    }
    // generated end

    fn has_exactly_one_true(iter: impl IntoIterator<Item = bool>) -> bool {
        iter.into_iter().filter(|x| *x).count() == 1
    }

    pub enum CmdSinkProg<'a> {
        Program(&'a Path),
        Cmdline(&'a [OsString]),
    }

    pub enum CmdSink<'a> {
        Stdout,
        File(&'a Path),
        Prog(CmdSinkProg<'a>),
    }

    impl HttpFileUploader {
        pub fn validate_or_exit(&self) {
            if !has_exactly_one_true([
                self.listen.is_some() || self.unix.is_some(),
                self.inetd,
                self.accept_tcp,
                self.accept_unix,
            ]) {
                eprintln!("Specify exactly one of --listen/--unix, --inetd or --accept");
                exit(1);
            }

            if !has_exactly_one_true([
                self.stdout,
                self.output.is_some(),
                self.program.is_some(),
                self.cmdline,
            ]) {
                eprintln!("Specify exactly one of --stdout, --output, --program or --cmdline");
                exit(1);
            }

            if self.fd.is_some() && !self.inetd && !self.accept_tcp && !self.accept_unix {
                eprintln!("--fd option is meaningless without --inetd or --accept");
                exit(1);
            }

            if self.cmdline {
                if self.argv.is_empty() {
                    eprintln!("Specify positional arguments to use --cmdline mode");
                    exit(1);
                }
            } else if !self.argv.is_empty() {
                eprintln!("No positional arguments expected unless --cmdline option is in use");
                exit(1);
            }

            if self.parallelism || self.parallelism_limit.is_some() {
                if self.output.is_some() || self.stdout {
                    eprintln!("--output or --stdout is incompatible with --parallelism/-j");
                    exit(1);
                }
                if self.once {
                    eprintln!("--once is not compatible with --parallelism/-j");
                    exit(1);
                }
            }
            if self.inetd && self.stdout && self.fd.is_none() {
                eprintln!("--inetd and --stdout are incompatible, unless --fd is also specified");
                exit(1);
            }
            if self.buffer_child_stdout && self.program.is_none() && !self.cmdline {
                eprintln!("--bufer-child-stdout only works with --program or --cmdline");
                exit(1);
            }
            if (self.remove_incomplete || self.rename_complete.is_some()) && self.output.is_none() {
                eprintln!("--remove-incomplete or --rename-complete must be used with --output");
                exit(1);
            }
            if (self.url || self.url_base64 || self.method) && self.program.is_none() && !self.cmdline {
                eprintln!("--url[-base64] or --method only works with --program or --cmdline");
                exit(1);
            }
            if self.url && self.url_base64 {
                eprintln!("--url and --url-base64 cannot be used together");
                exit(1);
            }
            if let Some(q) = self.queue {
                if self.once {
                    eprintln!("--queue is not compatible with --once");
                    exit(1);
                }
                if q == 0 {
                    eprintln!("--queue=0 does not work");
                    exit(1);
                }
            }
            if let Some(p) = self.parallelism_limit {
                if self.parallelism {
                    eprintln!("--parallelism-limit is meaningless with with --parallelism (unrestricted parallelism)");
                    exit(1);
                }
                if p == 0 {
                    eprintln!("-j 0 does not work");
                    exit(1);
                }
            }
            if self.parallelism && self.queue.is_some() {
                eprintln!("--queue is meaningless with unrestricted --parallelism");
                exit(1);
            }
            if self.no_multipart {
                if !self.allow_nonmultipart {
                    eprintln!("--no-multipart is meaningless without --allow-nonmultipart");
                    exit(1);
                }
                if self.require_upload || self.name.is_some() {
                    eprintln!("--require-upload or --name are incompatible with --no-multipart");
                    exit(1);
                }
            }

            #[cfg(not(unix))]
            if self.unix.is_some() {
                eprintln!("--unix option is UNIX-only");
                exit(1);
            }
            #[cfg(not(unix))]
            if self.accept_tcp || self.accept_unix {
                eprintln!("--accept-* options are UNIX-only");
                exit(1);
            }
            #[cfg(not(unix))]
            if self.fd.is_some() {
                eprintln!("--fd option is UNIX-only");
                exit(1);
            }
        }

        pub fn sink(&self) -> CmdSink<'_> {
            if self.stdout {
                return CmdSink::Stdout;
            }
            if let Some(ref path) = self.output {
                return CmdSink::File(path);
            }
            if let Some(ref path) = self.program {
                return CmdSink::Prog(CmdSinkProg::Program(path));
            }
            if self.cmdline {
                return CmdSink::Prog(CmdSinkProg::Cmdline(&self.argv));
            }
            unreachable!()
        }
    }
}

struct State {
    cmd: flags::HttpFileUploader,
    shutdown_tx: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

struct SendOnDrop(Option<tokio::sync::oneshot::Sender<()>>);
impl Drop for SendOnDrop {
    fn drop(&mut self) {
        if let Some(tx) = self.0.take() {
            let _ = tx.send(());
        }
    }
}

async fn handle_upload(
    state: Arc<State>,
    url: axum::extract::OriginalUri,
    rq: Request<Body>,
) -> anyhow::Result<Response> {
    let cmd = &state.cmd;
    let sink = cmd.sink();

    let mut upload_happened = false;
    let mut _process_exiter: Option<SendOnDrop> = None;

    let mut parts = RequestParts::new(rq);
    let method = parts.method().clone();
    let multipart: Multipart;
    let mut multipart = if cmd.no_multipart {
        None
    } else {
        if let Some(ct) = parts.headers().get(CONTENT_TYPE) {
            let ct = ct.as_bytes();
            if ct
                .split_at(19.min(ct.len()))
                .0
                .eq_ignore_ascii_case(b"multipart/form-data")
            {
                multipart = parts.extract().await?;
                Some(multipart)
            } else {
                None
            }
        } else {
            None
        }
    };

    type ChunksStream<'a> = Pin<Box<dyn Stream<Item = Result<Bytes, anyhow::Error>> + Send + 'a>>;

    let chosen_field: Option<Field<'_>> = if let Some(ref mut multipart) = multipart {
        loop {
            match multipart.next_field().await? {
                None => break None,
                Some(field) => {
                    let name = field.name();
                    if let Some(ref require_name) = cmd.name {
                        if name != Some(require_name) {
                            continue;
                        }
                    }
                    break Some(field);
                }
            }
        }
    } else {
        None
    };

    let chosen_stream: Option<ChunksStream> = if let Some(field) = chosen_field {
        Some(
            field
                .map_err(|x| anyhow::anyhow!("multipart error: {}", x))
                .boxed(),
        )
    } else {
        if cmd.allow_nonmultipart {
            if let Some(b) = parts.take_body() {
                Some(b.map_err(|x| x.into()).boxed())
            } else {
                None
            }
        } else {
            None
        }
    };

    macro_rules! official_start_of_the_upload {
        () => {
            #[allow(unused_assignments)]
            {
                upload_happened = true;
            }
            if cmd.once {
                _process_exiter = Some(SendOnDrop(state.shutdown_tx.lock().unwrap().take()));
            }
        };
    }

    match sink {
        CmdSink::Stdout => {
            if let Some(mut field) = chosen_stream {
                let mut so = tokio::io::stdout();
                official_start_of_the_upload!();

                while let Some(chunk) = field.next().await {
                    let mut chunk = chunk?;
                    so.write_all_buf(&mut chunk).await?;
                }
                so.flush().await?;
            }
        }
        CmdSink::File(path) => {
            if let Some(mut stream) = chosen_stream {
                let mut f = tokio::fs::File::create(path).await?;
                let mut remover: Option<RemoveOnDrop> = None;

                struct RemoveOnDrop<'a> {
                    path: &'a Path,
                    defused: bool,
                }
                impl<'a> Drop for RemoveOnDrop<'a> {
                    fn drop(&mut self) {
                        if !self.defused {
                            let _ = std::fs::remove_file(self.path);
                        }
                    }
                }

                if cmd.remove_incomplete {
                    remover = Some(RemoveOnDrop {
                        path,
                        defused: false,
                    })
                }

                official_start_of_the_upload!();
                while let Some(chunk) = stream.next().await {
                    let mut chunk = chunk?;
                    f.write_all_buf(&mut chunk).await?;
                }
                f.flush().await?;
                drop(f);

                if let Some(mut rod) = remover {
                    rod.defused = true;
                }

                if let Some(ref newpath) = cmd.rename_complete {
                    tokio::fs::rename(path, newpath).await?;
                }
            }
        }
        CmdSink::Prog(p) => 'skip_prog: {
            if chosen_stream.is_none() && cmd.require_upload {
                break 'skip_prog;
            }
            let progname: &OsStr = match p {
                CmdSinkProg::Program(p) => p.as_os_str(),
                CmdSinkProg::Cmdline(argv) => &argv[0],
            };
            let mut command = Command::new(progname);
            match p {
                CmdSinkProg::Program(_) => {}
                CmdSinkProg::Cmdline(argv) => {
                    command.args(&argv[1..]);
                }
            }
            if cmd.method {
                command.arg(method.to_string());
            }
            if cmd.url {
                command.arg(url.0.to_string());
            }
            if cmd.url_base64 {
                command.arg(base64::encode(url.0.to_string()));
            }
            command.stdin(std::process::Stdio::piped());
            if cmd.buffer_child_stdout {
                command.stdout(std::process::Stdio::piped());
            }
            #[cfg(not(unix))]
            command.kill_on_drop(true);
            let child = command.spawn()?;

            struct ChildWrapper(Child);

            #[cfg(unix)]
            impl Drop for ChildWrapper {
                fn drop(&mut self) {
                    if let Some(id) = self.0.id() {
                        unsafe {
                            libc::kill(id as libc::pid_t, libc::SIGINT);
                        }
                    }
                }
            }

            let mut child = ChildWrapper(child);

            let mut stdin = child
                .0
                .stdin
                .take()
                .expect("Tokio process::Child's stdin is None despite of prior piped call");
            official_start_of_the_upload!();

            let stdout_rx = if cmd.buffer_child_stdout {
                let (tx, rx) = tokio::sync::oneshot::channel();
                let mut stdout =
                    child.0.stdout.take().expect(
                        "Tokio process::Child's stdout is None despite of prior piped call",
                    );
                tokio::spawn(async move {
                    let mut b = Vec::with_capacity(1024);
                    let _ = stdout.read_to_end(&mut b).await;
                    let _ = tx.send(b);
                });
                Some(rx)
            } else {
                None
            };

            let mut premature_finish = false;
            if let Some(mut stream) = chosen_stream {
                loop {
                    tokio::select!(
                        ret = stream.next() => {
                            if let Some(chunk) = ret {
                                let mut chunk = chunk?;
                                if stdin.write_all_buf(&mut chunk).await.is_err() {
                                    premature_finish = true;
                                    break;
                                }
                            } else {
                                break;
                            }
                        }
                        _exit_code = child.0.wait() => {
                            premature_finish = true;
                            break;
                        }
                    );
                }
            }
            if !premature_finish {
                stdin
                    .shutdown()
                    .await
                    .context("shutting down child stdin")?;
            }
            drop(stdin);

            let code = child.0.wait().await.context("waiting for exit code")?;

            if let Some(stdout) = stdout_rx {
                let output = stdout.await.unwrap_or_default();
                // dirty hack to get text/plain content type easily. UB in theory, works in practice
                let output = unsafe { String::from_utf8_unchecked(output) };

                if code.success() && !premature_finish {
                    return Ok((StatusCode::OK, output).into_response());
                } else {
                    return Ok((StatusCode::INTERNAL_SERVER_ERROR, output).into_response());
                }
            } else if code.success() && !premature_finish {
                return Ok((StatusCode::OK, "Upload successful\n").into_response());
            } else {
                return Ok((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!(
                        "Process exited with code: {}.{}\n",
                        code,
                        if premature_finish {
                            " Process exited without fully reading its stdin."
                        } else {
                            ""
                        }
                    ),
                )
                    .into_response());
            }
        }
    }

    if !upload_happened && cmd.require_upload {
        if let Some(ref require_name) = cmd.name {
            return Ok((
                StatusCode::BAD_REQUEST,
                format!("Multipart form field `{}` is not found\n", require_name),
            )
                .into_response());
        } else {
            return Ok((
                StatusCode::BAD_REQUEST,
                "No multipart form field found to upload\n",
            )
                .into_response());
        }
    }
    if upload_happened {
        Ok((StatusCode::OK, "Upload successful\n").into_response())
    } else {
        Ok((
            StatusCode::BAD_REQUEST,
            "No upload happened and nothing occurred\n",
        )
            .into_response())
    }
}

trait SocketLike: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> SocketLike for T {}
type BoxedSocket = Box<dyn SocketLike + Send + Unpin>;

#[pin_project::pin_project]
struct CustomServer(#[pin] tokio::sync::mpsc::Receiver<BoxedSocket>);

impl hyper::server::accept::Accept for CustomServer {
    type Conn = BoxedSocket;

    type Error = anyhow::Error;

    fn poll_accept(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        match self.project().0.poll_recv(cx) {
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(c)) => Poll::Ready(Some(Ok(c))),
            Poll::Pending => Poll::Pending,
        }
    }
}

async fn async_main(cmd: flags::HttpFileUploader) -> anyhow::Result<()> {
    let (tx, rx) = tokio::sync::mpsc::channel::<BoxedSocket>(1);
    let (mut shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let mut tcp_listener = None;
    if let Some(la) = cmd.listen {
        tcp_listener = Some(tokio::net::TcpListener::bind(la).await?)
    }
    #[cfg(unix)]
    if cmd.accept_tcp {
        let fd = cmd.fd.unwrap_or(0);
        use std::os::unix::prelude::FromRawFd;
        let s = unsafe { std::net::TcpListener::from_raw_fd(fd) };
        s.set_nonblocking(true)?;
        tcp_listener = Some(tokio::net::TcpListener::from_std(s)?);
    }

    if let Some(s) = tcp_listener {
        let tx = tx.clone();
        tokio::spawn(async move {
            loop {
                match s.accept().await {
                    Ok((c, ca)) => {
                        if !cmd.quiet {
                            eprintln!("Incoming connection from {}", ca);
                        }
                        let _ = tx.send(Box::new(c)).await;
                    }
                    Err(e) => {
                        eprintln!("Error accepting from TCP socket: {}", e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });
    }

    #[cfg(unix)]
    let mut unix_listener = None;
    #[cfg(unix)]
    if let Some(ref path) = cmd.unix {
        let _ = std::fs::remove_file(path);
        unix_listener = Some(tokio::net::UnixListener::bind(path)?);
    }
    #[cfg(unix)]
    if cmd.accept_unix {
        let fd = cmd.fd.unwrap_or(0);
        use std::os::unix::prelude::FromRawFd;
        let s = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
        s.set_nonblocking(true)?;
        unix_listener = Some(tokio::net::UnixListener::from_std(s)?);
    }

    #[cfg(unix)]
    if let Some(s) = unix_listener {
        let tx = tx.clone();
        tokio::spawn(async move {
            loop {
                match s.accept().await {
                    Ok((c, _ca)) => {
                        if !cmd.quiet {
                            eprintln!("Incoming connection from a UNIX socket");
                        }
                        let _ = tx.send(Box::new(c)).await;
                    }
                    Err(e) => {
                        eprintln!("Error accepting from UNIX socket: {}", e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });
    }

    macro_rules! plan_shutdown {
        () => {
            tokio::spawn(async move {
                // kludge to avoid premature exit or needless linger after the end of request
                // but can't just trigger `shutdown_tx` immediately, as it would cause server to quit before serving the request
                tokio::task::yield_now().await;
                tokio::time::sleep(Duration::from_millis(10)).await;
                let _ = shutdown_tx.send(());
            });
            let (fake_tx,_fake_rx) = tokio::sync::oneshot::channel();
            shutdown_tx = fake_tx;
        }
    }

    #[cfg(unix)]
    if cmd.inetd && cmd.fd.is_none() {
        let si = tokio::io::stdin();
        let so = tokio::io::stdout();
        let s = readwrite::ReadWriteTokio::new(si, so);
        tx.try_send(Box::new(s))
            .unwrap_or_else(|_| panic!("Expected guranteed send to a channel with nonzero buffer"));
        plan_shutdown!();
    }

    #[cfg(unix)]
    if let Some(fd) = cmd.fd {
        if cmd.inetd {
            use std::os::unix::prelude::FromRawFd;
            let s = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
            s.set_nonblocking(true)?;
            let s = tokio::net::UnixStream::from_std(s)?;
            tx.try_send(Box::new(s)).unwrap_or_else(|_| {
                panic!("Expected guranteed send to a channel with nonzero buffer")
            });
            plan_shutdown!();
        }
    }

    #[axum_macros::debug_handler]
    async fn handle_upload2(
        Extension(state): Extension<Arc<State>>,
        uri: axum::extract::OriginalUri,
        rq: Request<Body>,
    ) -> Response {
        match handle_upload(state, uri, rq).await {
            Ok(x) => x,
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Error: {:#}\n", e),
            )
                .into_response(),
        }
    }

    let concurrencly_limit = if cmd.parallelism {
        None
    } else {
        Some(cmd.parallelism_limit.unwrap_or(1))
    };
    let queue = cmd.queue;

    let state = Arc::new(State {
        cmd,
        shutdown_tx: std::sync::Mutex::new(Some(shutdown_tx)),
    });
    let app = Router::new()
        .fallback(handle_upload2.into_service())
        .layer(Extension(state))
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(my_error_handler))
                .load_shed()
                .option_layer(queue.map(|x| BufferLayer::new(x)))
                .option_layer(concurrencly_limit.map(|x| ConcurrencyLimitLayer::new(x))),
        );

    let makeservice = app.into_make_service();

    let incoming = CustomServer(rx);

    hyper::server::Builder::new(incoming, hyper::server::conn::Http::new())
        .serve(makeservice)
        .with_graceful_shutdown(async {
            shutdown_rx.await.ok();
        })
        .await?;
    Ok(())
}

async fn my_error_handler(err: BoxError) -> (StatusCode, String) {
    if err.is::<tower::load_shed::error::Overloaded>() {
        (   StatusCode::TOO_MANY_REQUESTS,
        "Request is already being served and --parallelism is not specified (or -j limit is exceed) and no -Q is present or the queue is full".to_owned()
    )
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unhandled internal error: {}", err),
        )
    }
}

fn main() -> anyhow::Result<()> {
    let cmd = flags::HttpFileUploader::from_env_or_exit();
    cmd.validate_or_exit();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;
    rt.block_on(async_main(cmd))?;

    Ok(())
}
