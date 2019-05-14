# SCALAR
System Call Automated Logging and Recovery

## Dependencies
SCALAR requires libfuse 3 (both libraries and headers), as well as FUSE support
in the kernel. It also requires support for mount namespaces, PID namespaces,
IPC namespaces, and user namespaces.

## Building
Run `make`.

## Running
SCALAR comes in two pieces: a daemon, called `scalard`, and a client, called
`scalar`. `scalard` will output the logs to its STDOUT. To run SCALAR, first run
the daemon, `scalard`, as root. Then, to run a process inside SCALAR, run
`scalar <executable_path> <process_args>...`, also as root.
