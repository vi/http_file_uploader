# http_file_uploader

Simple low-level web server to serve file uploads with some shell scripting-friendly features. A bridge between Web's multipart/form-data file upload world and UNIX-ey files and command lines world. Somewhat close in spirit to CGI, but without the flexibility (hopefully with security instead).

HTTP listening features:

* Listening for connections on TCP address
* Listening for connections on UNIX path
* Using stdin/stdout to serve one connection, inetd-style
* Accepting connections from a pre-bound TCP or UNIX socket e.g. from SystemD socket activation service
* Decoding multipart request bodies, selecting specific field from it (or optionally just streaming the whole request body). Or just simply starting programs on each request (even without body).

Sink features:

* Dumping the file being received to stdout
* Saving the file to filesystem (and maybe moving it elsewhere if upload is finished successfully)
* Starting external program to handle the upload. The data would appear on stdin.

See "CLI usage message" section below for the exhausive list of options.

Most HTTP request parameters are ignored - it only concerns about the incoming data. Use nginx/caddy to filter and shape request and responses the way you like instead. You can select the field of the form to process, but other fields are ignored.

# Installation

Build it from source code with `cargo install --path .`, install from crates.io using `cargo install http_file_uploader` or download a pre-built version from [Github Releases](https://github.com/vi/http_file_uploader/releases/).

# Examples

```
$ httpfileuploader -l 127.0.0.1:8080 --stdout |
Incoming connection from 127.0.0.1:32876      | $ curl http://127.0.0.1:8080/ --form aaa=www
www                                           | Upload successful

$ httpfileuploade  -l 127.0.0.1:8080 -B -c --url -- echo
Incoming connection from 127.0.0.1:46750      | $ curl http://127.0.0.1:8080/asd?fgh
                                              | /asd?fgh

$ httpfileuploader  -l 127.0.0.1:8080 -o myupload.txt.tmp --rename-complete myupload.txt --once
Incoming connection from 127.0.0.1:48712      | $ curl http://127.0.0.1:8080 --form f=@Cargo.toml
                                              | Upload successful
$ cmp myupload.txt Cargo.toml

$ http_file_uploader -l 127.0.0.1:1234 -r -P -I --cmdline -- stdbuf -oL /bin/rev&
$ nc 127.0.0.1 1234
POST / HTTP/1.0
Content-Length: 1000

HTTP/1.0 200 OK
date: Thu, 27 Oct 2022 13:26:14 GMT

Hello, world
dlrow ,olleH
12345
54321
^C
```

# CLI usage message

```
http-file-uploader
  Special web server to allow shell scripts and other simple UNIX-ey programs to handle multipart/form-data HTTP  file uploads

ARGS:
    <argv>...
      Command line array for --cmdline option

OPTIONS:
    -l, --listen <addr>
      Bind and listen specified TCP socket

    -u, --unix <path>
      Optionally remove and bind this UNIX socket for listening incoming connections

    --inetd
      Read from HTTP request from stdin and write HTTP response to stdout

    --accept-tcp
      Expect file descriptor 0 (or specified) to be pre-bound listening TCP socket e.g. from systemd's socket activation
      You may want to specify `--fd 3` for systemd

    --accept-unix
      Expect file descriptor 0 (or specified) to be pre-bound listening UNIX socket e.g. from systemd's socket activation
      You may want to specify `--fd 3` for systemd

    --fd <fd>
      File descriptor to use for --inetd or --accept-... modes instead of 0.

    --once
      Serve only one successful upload, then exit.
      Failed child process executions are not considered as unsuccessful uploads for `--once` purposes, only invalid HTTP requests.
      E.g. trying to write to /dev/full does exit with --once, but failure to open --output file does not.

    -O, --stdout
      Dump contents of the file being uploaded to stdout.

    -o, --output <path>
      Save the file to specified location and overwrite it for each new upload

    -p, --program <path>
      Execute specified program each time the upload starts, without CLI parameters by default and file content as in stdin
      On UNIX, SIGINT is sent to the process if upload is terminated prematurely

    -c, --cmdline
      Execute command line (after --) each time the upload starts. URL is not propagated. Uploaded file content is in stdin.
      On UNIX, SIGINT is sent to the process if upload is terminated prematurely

    -n, --name <field_name>
      Restrict multipart field to specified name instead of taking first encountred field.

    -r, --require-upload
      Require a file to be uploaded, otherwise failing the request.

    -L, --parallelism
      Allow multiple uploads simultaneously without any limit

    -j, --parallelism-limit <limit>
      Limit number of upload-serving processes running in parallel.
      You may want to also use -Q option

    -Q, --queue <len>
      Number of queued waiting requests before starting failing them with 429. Default is no queue.
      Note that single TCP connection can issue multiple requests in parallel, filling up the queue.

    -B, --buffer-child-stdout
      Buffer child process output to return it to HTTP client as text/plain

    -I, --pipe
      Don't bother calculating Content-Length, instead pipe child process's stdout to HTTP reply chunk by chunk

    --remove-incomplete
      Remove --output file if the upload was interrupted

    --rename-complete <path>
      Move --output's file to new path after the upload is fully completed

    -U, --url
      Append request URL as additional command line parameter

    --url-base64
      Append request URL as additional command line parameter, base64-encoded

    -q, --quiet
      Do not announce new connections

    -P, --allow-nonmultipart
      Allow plain, non-multipart/form-data requests (and stream body chunks instead of form field's chunks)

    --no-multipart
      Don't try to decode multipart/form-data content, just stream request body as is always.

    -M, --method
      Append HTTP request method to the command line parameters (before --url if specified)

    -h, --help
      Prints help information.
```
