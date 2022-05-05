# A core dump collection tool for Linux

See `core(5)` for information about core dump processing in Linux.

This tool *attempts* to collect available information useful for post-crash
problem analysis. It is intended to be run by the Linux kernel by registering
it as core dump handler in in `proc` file system (`/proc/sys/kernel/core_pattern`).
Which means, that before use, it must be registered in it:

    sudo dumpcore --install

The program exists in two forms: a Shell script, immediately ready to use. And
a C version of the program, much faster (necessary, if you have a lot of
processes, all crashing at the same time).

Both support configuration in `/etc/dumpcore/config`, which allows to
set the directory for storing of the core dumps, analysis reports and logs,
the user/group to set on those files, and what `GDB` to use.

The analysis report is structured to contain end of data marker (a line with 
lone `end`) at the end of processing. Also, the user/group is set at the
end, so the coredump directory can be post-processed automatically.

# Caveats

The user and group names from the configuration files are resolved at the
moment of crash, from the initial (kernel) namespaces using standard C library
routines. This can fail if that resolving requires the context set up later.


