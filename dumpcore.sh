#!/bin/sh

# Note! This is executed as root in the initial namespace!

# To activate:
#
# sudo ./bin/dumpcore.sh --install=MAX_NUMBER_OF_CONCURRENT_COREDUMPS
#
# or
#
# echo "|$(realpath bin/dumpcore.sh) %P %u %I %s %E" >/proc/sys/kernel/core_pattern
# echo MAX_NUMBER_OF_CONCURRENT_COREDUMPS >/proc/sys/kernel/core_pipe_limit
#
# Choose MAX_NUMBER_OF_CONCURRENT_COREDUMPS to be a bit more than
# the number of parallel processes you're expecting to crash.
#
# When collecting core dumps, check that last line of core-xxx.txt is "end",
# otherwise the core dump is not saved yet.
#
# XXX This relies on the full path to the executable and the core being
# accessible in both initial and target mount namespaces. Which might be
# a wrong thing to rely on...

test -f /etc/dumpcore/config && . /etc/dumpcore/config
: "${CORE_USER:=root}"
: "${CORE_GROUP:=root}"
: "${CORE_DIR:=/var/log/dumpcore}"
: "${CORE_AUTOCLEAN:=Y}"
: "${GDB:=/usr/bin/gdb}"

if [ $# = 1 -a "${1%=*}" = '--install' ]; then
    arg=$(realpath "$0")
    if ! cd "$CORE_DIR" 2>/dev/null; then
	mkdir -p "$CORE_DIR" || echo >&2 'Crash reports may be lost!'
	chown "$CORE_USER:$CORE_GROUP" "$CORE_DIR"
    fi
    echo "|$arg %P %u %I %s %E" >/proc/sys/kernel/core_pattern
    arg="${1#--install}"
    arg="${arg#=}"
    if [ -n "$arg" ]; then
        echo "$arg" >/proc/sys/kernel/core_pipe_limit
    fi
    set -x
    cat /proc/sys/kernel/core_pattern
    cat /proc/sys/kernel/core_pipe_limit
    exit
fi

pid="$1"
exepath="$5"
core=$(mktemp --tmpdir="$CORE_DIR" core-XXXXXXXX)
exec 2>>"$core.log"
cat >"$core"
exec >>"$core.txt"
chown "$CORE_USER:$CORE_GROUP" "$core" "$core.log"
exe=$(readlink /proc/$pid/exe)
echo "CORE-OF: $exe

DUMPCORE_ARGS:"
for a in "$@"; do echo " $a"; done
echo "DUMPCORE_ARGS_END

PROC-$pid:"
find "/proc/$pid/root" "/proc/$pid/cwd" "/proc/$pid/fd" \
    -type l -printf ' %p -> %l\n'
echo "PROC-${pid}_END

ENVIRONMENT:"
xargs -n1 -0 echo '' <"/proc/$pid/environ"
echo 'ENVIRONMENT_END

PID_TRACE:'
get_ppid() {
    local name= pid=
    while read name pid; do
        test "$name" = 'PPid:' && break
    done <"/proc/$1/status"
    echo $pid
}
echo -n "$pid ($(read s</proc/$pid/comm;echo $s)) "
xargs -0 echo <"/proc/$pid/cmdline"
echo ' cwd:' $(readlink "/proc/$pid/cwd" 2>&1)
ppid=$(get_ppid $pid)
while [ -n "$ppid" -a "$ppid" != 1 ]; do
    echo -n "$ppid ($(read s</proc/$ppid/comm;echo $s)) "
    xargs -0 echo <"/proc/$ppid/cmdline"
    echo ' cwd:' $(readlink "/proc/$ppid/cwd" 2>&1)
    ppid=$(get_ppid $ppid)
done
echo 'PID_TRACE_END

GDB:'
gdb_cmd='
set print pretty on
set pagination off
set confirm off
printf "Threads:\n"
info threads
printf "Stack:\n"
info locals
info stack
printf "Environment:\n"
set $i=0
while environ[$i]
 if $i == 0
  printf "\n"
 end
 printf "%s\n", environ[$i++]
end
printf "\n"
quit'
printf '%s' "$gdb_cmd" |
nsenter -t "$pid" -m $GDB -q --nh --nx -ex 'set prompt' "$exe" "$core"
ret=$?
echo 'GDB_END
'
if [ "$ret" -gt 0 ]; then
    # /proc/<pid> has been cleaned up already, try to decode the core with the
    # path from command-line, it might be still accessible.
    echo 'GDB2:'
    exe2=$(echo "$exepath" |tr '!' '/')
    printf '%s' "$gdb_cmd" | $GDB -q --nh --nx -ex 'set prompt' "$exe2" "$core"
    echo 'GDB2_END
'
fi
case "$CORE_AUTOCLEAN" in
    [YyJjTt1])
        echo "CORE-AUTOCLEAN: $CORE_AUTOCLEAN"
        rm "$core"
esac
# Done. Set the completion marker.
echo 'end'
exec >/dev/null # close $core.txt
chown "$CORE_USER:$CORE_GROUP" "$core.txt"
