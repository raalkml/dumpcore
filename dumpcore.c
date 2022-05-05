/*
 * Note! This is executed as root in the initial namespace!
 *
 * To activate:

    cc -Wall -O2 -g -o dumpcore dumpcore.c &&
    sudo ./dumpcore --install

 * "--install" can be followed by "=MAX_NUMBER_OF_CONCURRENT_COREDUMPS",
 * where MAX_NUMBER_OF_CONCURRENT_COREDUMPS is 100 by default.
 *
 * The installation routine does something like this:

    echo "|$(realpath bin/dumpcore) %P %u %I %s %E" >/proc/sys/kernel/core_pattern
    echo MAX_NUMBER_OF_CONCURRENT_COREDUMPS >/proc/sys/kernel/core_pipe_limit

 * Choose MAX_NUMBER_OF_CONCURRENT_COREDUMPS to be a bit more than
 * the number of parallel processes you're expecting to crash at once.
 *
 * When collecting core dumps, check that last line of core-xxx.txt is "end",
 * otherwise the core dump is not saved yet.
 *
 * XXX This code sometimes relies on the full path to the executable and the
 * core being accessible in both initial and target mount namespaces. Which
 * might be a wrong thing to rely on...
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/vfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <grp.h>
#include <pwd.h>

#ifndef DUMPCORE_CONFIG
#define DUMPCORE_CONFIG "/etc/dumpcore/config"
#endif
static char DEFAULT_CORE_DIR[] = "/var/log/dumpcore";
static char DEFAULT_CORE_USER[] = "root";
static char DEFAULT_CORE_GROUP[] = "root";
static char DEFAULT_CORE_AUTOCLEAN[] = "Y"; /* remove core file after analysis */
static char DEFAULT_GDB[] = "/usr/bin/gdb";

static char STR_ERROR[] = "*error*";

static int write_file(const char *name, const void *data, int len)
{
    ssize_t wr;
    int ret, fd = open(name, O_WRONLY);

    if (fd == -1)
        return -1;
    if (len == -1)
        len = strlen((const char *)data);
    ret = wr = write(fd, data, len);
    if (wr == -1)
        ret = -errno;
    if (close(fd) == -1)
        ret = wr < 0 ? ret : -errno;
    return ret;
}

static char *read_symlink(int dirfd, const char *name)
{
    size_t size = PATH_MAX / 2;
    char *buf = malloc(size);
    ssize_t ret;

    while ((ret = readlinkat(dirfd, name, buf, size)) == (ssize_t)size)
        buf = realloc(buf, size += PATH_MAX / 4);
    if (ret == -1) {
        free(buf);
        return STR_ERROR;
    }
    buf[ret] = '\0';
    return buf;
}

static char *read_file(int dfd, const char *name, void *result, size_t size, ssize_t *used)
{
    ssize_t ret;
    size_t blksz, rd = 0;
    int fd;
    char *buf = NULL;

    fd = openat(dfd, name, O_RDONLY);
    if (fd == -1)
        return STR_ERROR;
    if (result) {
        if (!size)
            goto close_ret;
        do {
            ret = read(fd, (char *)result + rd, size - rd);
            if (ret == 0)
                break;
            if (ret == -1)
                goto save_errno_ret;
            rd += ret;
        } while (rd < size);
        if (rd == size)
            --ret;
        *((char *)result + rd) = '\0';
        if (used) *used = rd;
        goto close_ret;
    }
    blksz = size;
    if (!blksz)
        blksz = BUFSIZ;
    buf = malloc(blksz);
    if (!buf)
        goto out_of_mem;
    for (;;) {
        ret = read(fd, buf + rd, blksz);
        if (ret == 0)
            break;
        if (ret == -1)
            goto save_errno_ret;
        rd += ret;
        buf = realloc(buf, rd + blksz);
        if (!buf)
            goto out_of_mem;
    }
    if (used) *used = rd;
    *((char *)buf + rd) = '\0';
    buf = realloc(buf, rd + 1);
    result = buf;
close_ret:
    close(fd);
    return result;
out_of_mem:
    errno = ENOMEM;
save_errno_ret:
    ret = errno;
    free(buf);
    close(fd);
    errno = ret;
    return STR_ERROR;
}

static void replace_inplace(char *s, char a, char b)
{
    while (*s) {
        s = strchr(s, a);
        if (!s)
            break;
        *s++ = b;
    }
}

static int do_install(char *argv0, const char *arg)
{
    // <pid> <target-pidns-pid> <uid> <signal> <exe-path-/-!>
    static const char core_pattern[] = "/proc/sys/kernel/core_pattern";
    static const char core_pipe_limit[] = "/proc/sys/kernel/core_pipe_limit";
    static const char pattern[] = " %P %p %s %E";
    char *absexe;
    char *exe = read_symlink(AT_FDCWD, "/proc/self/exe");
    if (exe == STR_ERROR) {
        fprintf(stderr, "Cannot read /proc (%m), falling back to %s\n", argv0);
        exe = argv0;
    }
    absexe = realpath(exe, NULL);
    if (!absexe) {
        fprintf(stderr, "Cannot use %s: %m\n", exe);
        return 1;
    }
    if (exe != argv0)
        free(exe);
    // man 5 core
    // XXX kernels before 5.3 split the command into argument after
    // XXX expanding the pattern, breaking names with spaces. Especially
    // XXX badly with multiple spaces, which collapse. The processing
    // XXX of such path names (required if exe symlink is gone) involves
    // XXX a search for the files.
    char *s = malloc(1 + strlen(absexe) + sizeof(pattern));
    strcpy(s, "|");
    strcat(s, absexe);
    strcat(s, pattern);
    int ret = 0;
    printf("'|%s%s' >%s\n", absexe, pattern, core_pattern);
    if (write_file(core_pattern, s, -1) < 0) {
        fprintf(stderr, "%s: %m\n", core_pattern);
        ret = 1;
    }
    if (!*arg)
        arg = "100";
    if (*arg == '=')
        ++arg;
    if (*arg) {
        printf("'%s' >%s\n", arg, core_pipe_limit);
        if (write_file(core_pipe_limit, arg, -1) < 0) {
            fprintf(stderr, "%s: %m\n", core_pipe_limit);
            ret = 1;
        }
    }
    return ret;
}

static char *CORE_DIR = DEFAULT_CORE_DIR;
static char *CORE_USER = DEFAULT_CORE_USER;
static char *CORE_GROUP = DEFAULT_CORE_GROUP;
static char *CORE_AUTOCLEAN = DEFAULT_CORE_AUTOCLEAN;
static char *GDB = DEFAULT_GDB;

struct proc_file {
    int fd, err;
    const char *name;
};

enum {
    PID_NS_MNT,
    PID_ENVIRON,
};
static struct proc_file pid_file[] = {
    [PID_NS_MNT]  = { -1, 0, "ns/mnt" },
    [PID_ENVIRON] = { -1, 0, "environ" },
};
static int proc_pid_fd = -1, proc_pid_fd_errno;
static long core_pid = -1, core_ns_pid = -1, core_signal = -1;
static char *core_exe = NULL, *proc_exe = NULL, *proc_cwd = NULL;
static char *proc_root = NULL;
static char *core_file, *dump_txt, *dump_errors;

static char *trim_lf(char *s)
{
    char *value = s;
    s = strchr(s, '\n');
    if (s)
        *s = '\0';
    return value;
}

static void do_param(const char *param, const char *pattern,
                    char **value, char *keep, char *s)
{
    size_t len = strlen(pattern);
    if (memcmp(param, pattern, len) != 0 || param[len] != '=')
        return;
    if (*value != keep)
        free(*value);
    *value = strdup(trim_lf(s));
}

static void load_config(const char *config_file)
{
    char line[8192];
    FILE *fp = fopen(config_file, "r");
    if (!fp)
        return;
    while (fgets(line, sizeof(line), fp)) {
        char *s = line;
        while ('\t' == *s || '\x20' == *s || '\r' == *s)
            ++s;
        if ('\n' == *s || '#' == *s) // empty line or comment line
            continue;
        char *param = s;
        while (*s)
            if (*s++ == '=')
                break;
        if ('\n' == *s || s == param) // no value or no parameter
            continue;
        do_param(param, "CORE_DIR", &CORE_DIR, DEFAULT_CORE_DIR, s);
        do_param(param, "CORE_USER", &CORE_USER, DEFAULT_CORE_USER, s);
        do_param(param, "CORE_GROUP", &CORE_GROUP, DEFAULT_CORE_GROUP, s);
        do_param(param, "CORE_AUTOCLEAN", &CORE_AUTOCLEAN, DEFAULT_CORE_AUTOCLEAN, s);
        do_param(param, "GDB", &GDB, DEFAULT_GDB, s);
    }
    fclose(fp);
}

/*
 * Open the pids directory and reserves the next two descriptors to avoid
 * clashing with stdout and stderr. The reserved descriptors will be
 * re-used later when redirecting stdout/stderr.
 */
static int open_pid(const char *pid)
{
    char name[64];

    strcpy(name, "/proc/");
    strcpy(name + 6, pid);
    proc_pid_fd = open(name, O_PATH | O_CLOEXEC);
    proc_pid_fd_errno = errno;
    if (proc_pid_fd == STDOUT_FILENO)
        proc_pid_fd = fcntl(proc_pid_fd, F_DUPFD_CLOEXEC, 1);
    if (proc_pid_fd == STDERR_FILENO)
        proc_pid_fd = fcntl(proc_pid_fd, F_DUPFD_CLOEXEC, 1);
    return proc_pid_fd;
}

static void open_pid_files()
{
    unsigned i;

    for (i = 0; i < sizeof(pid_file) / sizeof(*pid_file); ++i) {
        if (!pid_file[i].name)
            continue;
        pid_file[i].fd = openat(proc_pid_fd, pid_file[i].name,
                                O_RDONLY | O_CLOEXEC);
        pid_file[i].err = errno;
    }
}

static char *redirect_fd(int tgtfd, const char *core_file, const char *end)
{
    int len = strlen(core_file);
    char *file = malloc(len + strlen(end));
    strcpy(file, core_file);
    strcat(file, end);
    int fd = open(file, O_WRONLY | O_APPEND | O_CREAT, 0640);
    if (fd == -1) // log to kernel
        return NULL;
    dup2(fd, tgtfd);
    if (fd != tgtfd)
        close(fd);
    return file;
}

static void copy_core(int fd)
{
    char *buf;
    int p[2];
    long long done = 0, sdone = 0;
    struct statfs fs;
    size_t block_size = 16 * BUFSIZ;

    if (fstatfs(fd, &fs) != -1)
        block_size = 64 * fs.f_bsize;

    done = 0;
    while (1) {
        ssize_t ret;
        ret = splice(STDIN_FILENO, NULL, fd, NULL, block_size, SPLICE_F_MOVE);
        if (ret == 0) {
            sdone = done;
            goto read_write;
        }
        if (ret == -1) {
            fprintf(stderr, "splice(direct): %m\n");
            if (!done)
                goto splice_copy;
            break;
        }
        done += ret;
    }
    goto close_stdin;
splice_copy:
    fprintf(stderr, "fallback to pipe+splice\n");
    if (pipe(p) == -1)
        goto read_write;
    while (1) {
        ssize_t ret;
        ret = splice(STDIN_FILENO, NULL, p[1], NULL, block_size,
                     SPLICE_F_MOVE);
        if (ret == 0){
            close(p[0]);
            close(p[1]);
            sdone = done;
            goto read_write;
        }
        if (ret == -1) {
            fprintf(stderr, "splice: %m\n");
            if (!done)
                goto read_write;
            break;
        }
        done += ret;
        while (ret) {
            ssize_t wr = splice(p[0], NULL, fd, NULL, block_size,
                                SPLICE_F_MOVE);
            if (wr == -1) {
                fprintf(stderr, "splite write: %m\n");
                break;
            }
            ret -= wr;
        }
    }
    close(p[0]);
    close(p[1]);
    goto close_stdin;
read_write:
    buf = malloc(block_size);
    while (1) {
        ssize_t ret = read(STDIN_FILENO, buf, block_size);
        char *p = buf;
        if (!ret) {
            if (sdone != done)
                fprintf(stderr, "core: read got more %lld\n", done - sdone);
            break;
        }
        if (EINTR == errno)
            continue;
        if (ret == -1) {
            fprintf(stderr, "read %m\n");
            break;
        }
        done += ret;
        while (ret) {
            ssize_t wr = write(fd, p, ret);
            if (wr == -1) {
                fprintf(stderr, "write %m\n");
                goto clean_exit;
            }
            ret -= wr;
            p += wr;
            fprintf(stderr, "saved %ld\n", (long)wr);
        }
    }
clean_exit:
    free(buf);
close_stdin:
    /*
     * Try to close the core file descriptor, making sure its index in the
     * processes file table stays occupied.
     * Because something sooner or later will not expect open(2) to return 0.
     */
    p[0] = open("/dev/null", O_RDONLY);
    if (p[0] != -1) {
        dup2(p[0], STDIN_FILENO);
        close(p[0]);
    }
    fdatasync(fd);
}

static void dump_proc(void)
{
    DIR *dir;

    printf("PROC-%ld:\n", core_pid);
    proc_root = read_symlink(proc_pid_fd, "root");
    printf(" root -> %s\n", proc_root);
    proc_cwd = read_symlink(proc_pid_fd, "cwd");
    printf(" cwd -> %s\n", proc_cwd);
    int dfd = openat(proc_pid_fd, "fd", O_DIRECTORY | O_RDONLY | O_CLOEXEC);
    if (dfd == -1)
        fprintf(stderr, "/proc/%ld/fd: %m\n", core_pid);
    dir = fdopendir(dfd);
    if (dir) {
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            if (ent->d_name[0] == '.')
                continue;
            char *t = read_symlink(dirfd(dir), ent->d_name);
            printf(" fd/%s -> %s\n", ent->d_name, t);
            if (t != STR_ERROR)
                free(t);
        }
        closedir(dir);
    }
    printf("PROC-%ld_END\n\n", core_pid);
}

static int fputc_escaped(int ch, FILE *fp, const char *nul)
{
    switch (ch) {
    case '\0':
        fputs(nul, fp);
        goto ret;
    case '\a': ch = 'a'; break;
    case '\b': ch = 'b'; break;
    case '\f': ch = 'f'; break;
    case '\t': ch = 't'; break;
    case '\n': ch = 'n'; break;
    case '\r': ch = 'r'; break;
    case '\v': ch = 'v'; break;
    case '\\': break;
    default: goto out;
    }
    fputc('\\', fp);
out:
    fputc(ch, fp);
ret:
    return ch;
}

static void dump_proc_environ(void)
{
    FILE *fp;

    fputs("ENVIRONMENT:\n", stdout);
    fp = fdopen(pid_file[PID_ENVIRON].fd, "r");
    if (fp) {
        int ch;
        while ((ch = fgetc(fp)) != EOF)
            fputc_escaped(ch, stdout, "\n");
        fclose(fp);
        pid_file[PID_ENVIRON].fd = -1;
    } else {
        fprintf(stderr, "/proc/%ld/%s: %s\n",
                core_pid, pid_file[PID_ENVIRON].name,
                strerror(pid_file[PID_ENVIRON].err));
    }
    fputs("ENVIRONMENT_END\n\n", stdout);
}

static void dump_proc_environ_var(int dfd, long pid, const char *vars[])
{
    char name[64];
    char *s = name;
    int ch;
    FILE *fp;
    int fd;

    fd = openat(dfd, "environ", O_RDONLY);
    if (fd == -1)
        goto fail;
    fp = fdopen(fd, "r");
    if (!fp)
        goto fail;
    while ((ch = fgetc(fp)) != EOF) {
        if ('=' != ch) {
            *s++ = ch;
            if (s - name < (int)sizeof(name))
                continue;
            /* var name too long */
        } else {
            int i;
            for (i = 0; vars[i]; ++i)
                if ((int)strlen(vars[i]) == s - name &&
                    memcmp(name, vars[i], s - name) == 0)
                    break;
            if (vars[i]) {
                fputc(' ', stdout);
                fwrite(name, s - name, 1, stdout);
                fputc(ch, stdout);
                while ((ch = fgetc(fp)) != EOF && ch)
                    fputc_escaped(ch, stdout, NULL);
                fputc('\n', stdout);
                goto nextvar;
            }
        }
        while ((ch = fgetc(fp)) != EOF && ch);
nextvar:
        s = name;
    }
    fclose(fp);
    return;
fail:
    fprintf(stderr, "/proc/%ld/environ: %m\n", pid);
}

static char *is_proc_state(const char *s)
{
    if ((('A' <= *s && *s <= 'Z') || ('a' <= *s && *s <= 'z')) &&
        s[1] == ' ')
        return (char *)s + 1;
    return NULL;
}

static char *is_proc_number(const char *s)
{
    const char *e = s;
    while ('0' <= *e && *e <= '9')
        ++e;
    if (e > s) {
        if (!*e || ' ' == *e)
            return (char *)e;
    }
    return NULL;
}

static void trace_pid(void)
{
    char buf[BUFSIZ];
    long pid = core_pid;

    fputs("PID_TRACE:\n", stdout);
    do {
        ssize_t used;
        long ppid = -1;
        int dfd;
        snprintf(buf, sizeof(buf), "/proc/%ld", pid);
        dfd = open(buf, O_PATH | O_CLOEXEC);
        if (dfd == -1) {
            fprintf(stderr, "pid trace: %s: %m\n", buf);
            goto done;
        }
        char *s = read_file(dfd, "stat", buf, sizeof(buf), NULL);
        char *e = is_proc_number(s);
        if (!e) goto done; /* <pid> <SP> */
        ++e;
        if ('(' != *e) goto done;
        ++e;
        while (*e) { /* (comm) <state> <ppid> */
            if (')' == *e && ' ' == e[1]) {
                const char *p_ppid = is_proc_state(e + 2);
                if (p_ppid) {
                    char *t = is_proc_number(++p_ppid);
                    if (t) {
                        *t = '\0';
                        ppid = strtol(p_ppid, NULL, 10);
                        printf("%.*s", (int)(p_ppid - s), s);
                        break;
                    }
                }
            }
            ++e;
        }
        s = read_file(dfd, "cmdline", NULL, 256, &used);
        if (s == STR_ERROR)
            printf("%m\n");
        else {
            e = s;
            while (e - s < used)
                fputc_escaped(*e++, stdout, " ");
            fputc('\n', stdout);
            /*
             * If argv[0] or argv[1] hint at this process being related to
             * clean-robot, try to look for interesting envars in its
             * environment.
             */
            static const char clean_robot[] = "clean-robot";
            e = strstr(s, clean_robot);
            if (!e)
                e = strstr(s + strlen(s) + 1, clean_robot);
            if (e) {
                static const char *vars[] = {
                    "NIGHTLY_WORK_DIR",
                    "CLEAN_ROBOT_LOGDIR",
                    "NIGHTLY_REPO",
                    NULL
                };
                dump_proc_environ_var(dfd, pid, vars);
            }
            free(s);
        }
        s = read_symlink(dfd, "cwd");
        printf(" cwd: %s%s\n", s, s == STR_ERROR ? strerror(errno) : "");
        if (s != STR_ERROR)
            free(s);
        pid = ppid;
    } while (pid > 0);
done:
    fputs("PID_TRACE_END\n\n", stdout);
}

static int run_gdb(const char *exe)
{
    static const char gdb_cmd[] =
        "set print pretty on\n"
        "set pagination off\n"
        "set confirm off\n"
        "printf \"Threads:\\n\"\n"
        "info threads\n"
        "printf \"Stack:\\n\"\n"
        "info locals\n"
        "info stack\n"
        "printf \"Environment:\\n\"\n"
        "set $i=0\n"
        "while environ[$i]\n"
        " if $i == 0\n"
        "  printf \"\\n\"\n"
        " end\n"
        " printf \"%s\\n\", environ[$i++]\n"
        "end\n"
        "quit\n";
    int status = -1;
    int fd[2];
    pid_t pid;

    fflush(stdout);
    if (pipe(fd) == -1) {
        fprintf(stderr, "pipe (gdb): %m\n");
        goto end;
    }
    pid = vfork();
    switch (pid) {
    case -1:
        fprintf(stderr, "fork (gdb): %m\n");
        goto end;
    case 0:
        close(fd[1]);
        dup2(fd[0], STDIN_FILENO);
        if (fd[0] != STDIN_FILENO)
            close(fd[0]);
        if (pid_file[PID_NS_MNT].fd == -1)
            fprintf(stderr, "gdb: /proc/%ld/%s: %s\n",
                    core_pid, pid_file[PID_NS_MNT].name,
                    strerror(pid_file[PID_NS_MNT].err));
        else if (setns(pid_file[PID_NS_MNT].fd, CLONE_NEWNS) == -1)
            fprintf(stderr, "gdb (setns): /proc/%ld/%s): %m\n",
                    core_pid, pid_file[PID_NS_MNT].name);
        if (exe && access(exe, R_OK) != 0)
            fprintf(stderr, "GDB: %s: %m\n", exe);
        execlp(GDB, "gdb", "-q", "--nh", "--nx", "-ex", "set prompt",
               exe ? exe : "/dev/null", core_file, NULL);
        fprintf(stderr, "%s: %m\n", GDB);
        exit(2);
    }
    close(fd[0]);
    if (write(fd[1], gdb_cmd, sizeof(gdb_cmd)) == -1)
        fprintf(stderr, "write (gdb cmd): %m\n");
    close(fd[1]);
    if (waitpid(pid, &status, 0) == -1)
        fprintf(stderr, "wait (gdb): %m\n");
end:
    return status;
}

static void log_wait_status(const char *label, int status)
{
    if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
        fprintf(stderr, "%s: finished with %d\n", label, WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
        fprintf(stderr, "%s: killed (%s)\n", label, strsignal(WTERMSIG(status)));
}

static void fix_owner()
{
    struct passwd *pw = getpwnam(CORE_USER);
    struct group *gr = getgrnam(CORE_GROUP);
    uid_t uid = -1;
    gid_t gid = -1;

    if (pw)
        uid = pw->pw_uid;
    if (gr)
        gid = gr->gr_gid;
    if (gid == (gid_t)-1 && pw)
        gid = pw->pw_gid;
    if (chown(core_file, uid, gid) == -1)
        perror("chown core");
    if (fchown(STDOUT_FILENO, uid, gid) == -1)
        perror("chown core.txt");
    if (fchown(STDERR_FILENO, uid, gid) == -1)
        perror("chown core.log");
}

int main(int argc, char *argv[])
{
    static const char core_XXX[] = "/core-XXXXXX";
    int core_fd, i;

    if (argc == 2 && strncmp(argv[1], "--install", 9) == 0 &&
        (argv[1][9] == '=' || argv[1][9] == '\0'))
        return do_install(argv[0], argv[1] + 9);
    if (argc > 1) {
        open_pid(argv[1]);
        open_pid_files();
        core_pid = strtol(argv[1], NULL, 10);
    }
    if (argc > 2)
        core_ns_pid = strtol(argv[2], NULL, 10);
    if (argc > 3)
        core_signal = strtol(argv[3], NULL, 10);
    if (argc > 4)
        /*
         * The subsequent arguments may contain parts of exe file name in the
         * kernels before 5.3.x! See "man 5 core".
         */
        core_exe = argv[4];

    load_config(DUMPCORE_CONFIG);

    core_file = malloc(strlen(CORE_DIR) + sizeof(core_XXX));
    strcpy(core_file, CORE_DIR);
    strcat(core_file, core_XXX);
    core_fd = mkstemp(core_file);
    if (core_fd < 0) {
        // TODO try to complain into kernel log, because STDERR_FILENO is not open
        // fprintf(stderr, "%s: %m\n", core_file);
        return 1;
    }
    /*
     * Have to make sure core_fd does not occupy stdout/stderr,
     * or the redirection of those will close it.
     */
    if (core_fd == STDOUT_FILENO)
        core_fd = dup(core_fd);
    if (core_fd == STDERR_FILENO)
        core_fd = dup(core_fd);
    dump_errors = redirect_fd(STDERR_FILENO, core_file, ".log");
    dump_txt = redirect_fd(STDOUT_FILENO, core_file, ".txt");
    if (proc_pid_fd != -1) {
        proc_exe = read_symlink(proc_pid_fd, "exe");
        if (proc_exe == STR_ERROR)
            proc_exe = NULL;
    }
    printf("CORE-OF: %s\n\n", proc_exe ? proc_exe : core_exe);
    fputs("DUMPCORE_ARGS:\n", stdout);
    for (i = 1; argv[i]; ++i) {
        fputc(' ', stdout);
        fputs(argv[i], stdout);
        fputc('\n', stdout);
    }
    fputs("DUMPCORE_ARGS_END\n\n", stdout);
    if (core_pid != -1) {
        dump_proc();
        dump_proc_environ();
        trace_pid();
    }
    copy_core(core_fd);
    close(core_fd);
    if (core_pid != -1) {
        int status = 0;
        if (proc_exe) {
            fputs("GDB:\n", stdout);
            status = run_gdb(proc_exe);
            fputs("\nGDB_END\n\n", stdout);
            log_wait_status(GDB, status);
        }
        if (core_exe) {
            if (!proc_exe)
                fprintf(stderr, "GDB: no /proc/self/exe\n");
            else if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
                fprintf(stderr, "GDB failed: %d\n", WEXITSTATUS(status));
            else if (WIFSIGNALED(status))
                fprintf(stderr, "GDB was killed: %d\n", WTERMSIG(status));
            else
                goto gdb_done;
            replace_inplace(core_exe, '!', '/');
            fputs("GDB2:\n", stdout);
            status = run_gdb(core_exe);
            fputs("\nGDB2_END\n\n", stdout);
            log_wait_status(GDB, status);
        }
gdb_done:
        ;
    }
    int core_autoclean = !!strchr("YyJjTt1", CORE_AUTOCLEAN[0]);
    if (core_autoclean)
        printf("CORE-AUTOCLEAN: %s\n", CORE_AUTOCLEAN);
    fputs("end\n", stdout);
    fflush(stdout);
    fix_owner();
    if (core_autoclean)
        unlink(core_file);
    return 0;
}

