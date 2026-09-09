# A core dump collection tool for Linux

See `core(5)` for information about core dump processing in Linux.

This tool *attempts* to collect available information useful for post-crash
problem analysis. It is intended to be run by the Linux kernel, registered
as core dump handler in `proc` file system (`/proc/sys/kernel/core_pattern`).
The tool has a built-in registration routine:

    sudo dumpcore --install

The routine sets `core_pattern` and `core_pipe_limit`.

The tool is implemented in three different ways: a Shell script, which is
immediately ready to use but is very slow; and Rust and C implementations,
which are much faster. The performance advantage becomes necessary, when you
have a lot of processes, all crashing at the same time (e.g. during a test run).

All implementations support configuration through `/etc/dumpcore/config`,
which allows setting the directory which will collect the core dumps, analysis
reports, and logs. The configuration also allows setting the file ownership,
and the debugger (`GDB`) executable used to extract the stack trace.

The analysis report is structured to contain an end-of-data marker (a line
containing the `end` string) at the end of processing. Also, the file
ownership is set at the end of the processing, so the coredump directory can
be post-processed automatically.

# Caveats

The user and group names from the configuration files are resolved at the
moment of crash, from the initial (kernel) namespaces using standard C library
routines. This can fail if that resolving requires the context set up later.


