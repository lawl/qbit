#ifndef SYSCALL_LIST_H_
#define SYSCALL_LIST_H_
int syscall_nr_by_name(char *name) {
#ifdef SYS__llseek
if(strcmp("SYS__llseek", name) == 0) return SYS__llseek;
#endif /* SYS__llseek */
#ifdef SYS__newselect
if(strcmp("SYS__newselect", name) == 0) return SYS__newselect;
#endif /* SYS__newselect */
#ifdef SYS__sysctl
if(strcmp("SYS__sysctl", name) == 0) return SYS__sysctl;
#endif /* SYS__sysctl */
#ifdef SYS_access
if(strcmp("SYS_access", name) == 0) return SYS_access;
#endif /* SYS_access */
#ifdef SYS_acct
if(strcmp("SYS_acct", name) == 0) return SYS_acct;
#endif /* SYS_acct */
#ifdef SYS_add_key
if(strcmp("SYS_add_key", name) == 0) return SYS_add_key;
#endif /* SYS_add_key */
#ifdef SYS_adjtimex
if(strcmp("SYS_adjtimex", name) == 0) return SYS_adjtimex;
#endif /* SYS_adjtimex */
#ifdef SYS_afs_syscall
if(strcmp("SYS_afs_syscall", name) == 0) return SYS_afs_syscall;
#endif /* SYS_afs_syscall */
#ifdef SYS_alarm
if(strcmp("SYS_alarm", name) == 0) return SYS_alarm;
#endif /* SYS_alarm */
#ifdef SYS_bdflush
if(strcmp("SYS_bdflush", name) == 0) return SYS_bdflush;
#endif /* SYS_bdflush */
#ifdef SYS_break
if(strcmp("SYS_break", name) == 0) return SYS_break;
#endif /* SYS_break */
#ifdef SYS_brk
if(strcmp("SYS_brk", name) == 0) return SYS_brk;
#endif /* SYS_brk */
#ifdef SYS_capget
if(strcmp("SYS_capget", name) == 0) return SYS_capget;
#endif /* SYS_capget */
#ifdef SYS_capset
if(strcmp("SYS_capset", name) == 0) return SYS_capset;
#endif /* SYS_capset */
#ifdef SYS_chdir
if(strcmp("SYS_chdir", name) == 0) return SYS_chdir;
#endif /* SYS_chdir */
#ifdef SYS_chmod
if(strcmp("SYS_chmod", name) == 0) return SYS_chmod;
#endif /* SYS_chmod */
#ifdef SYS_chown
if(strcmp("SYS_chown", name) == 0) return SYS_chown;
#endif /* SYS_chown */
#ifdef SYS_chown32
if(strcmp("SYS_chown32", name) == 0) return SYS_chown32;
#endif /* SYS_chown32 */
#ifdef SYS_chroot
if(strcmp("SYS_chroot", name) == 0) return SYS_chroot;
#endif /* SYS_chroot */
#ifdef SYS_clock_adjtime
if(strcmp("SYS_clock_adjtime", name) == 0) return SYS_clock_adjtime;
#endif /* SYS_clock_adjtime */
#ifdef SYS_clock_getres
if(strcmp("SYS_clock_getres", name) == 0) return SYS_clock_getres;
#endif /* SYS_clock_getres */
#ifdef SYS_clock_gettime
if(strcmp("SYS_clock_gettime", name) == 0) return SYS_clock_gettime;
#endif /* SYS_clock_gettime */
#ifdef SYS_clock_nanosleep
if(strcmp("SYS_clock_nanosleep", name) == 0) return SYS_clock_nanosleep;
#endif /* SYS_clock_nanosleep */
#ifdef SYS_clock_settime
if(strcmp("SYS_clock_settime", name) == 0) return SYS_clock_settime;
#endif /* SYS_clock_settime */
#ifdef SYS_clone
if(strcmp("SYS_clone", name) == 0) return SYS_clone;
#endif /* SYS_clone */
#ifdef SYS_close
if(strcmp("SYS_close", name) == 0) return SYS_close;
#endif /* SYS_close */
#ifdef SYS_creat
if(strcmp("SYS_creat", name) == 0) return SYS_creat;
#endif /* SYS_creat */
#ifdef SYS_create_module
if(strcmp("SYS_create_module", name) == 0) return SYS_create_module;
#endif /* SYS_create_module */
#ifdef SYS_delete_module
if(strcmp("SYS_delete_module", name) == 0) return SYS_delete_module;
#endif /* SYS_delete_module */
#ifdef SYS_dup
if(strcmp("SYS_dup", name) == 0) return SYS_dup;
#endif /* SYS_dup */
#ifdef SYS_dup2
if(strcmp("SYS_dup2", name) == 0) return SYS_dup2;
#endif /* SYS_dup2 */
#ifdef SYS_dup3
if(strcmp("SYS_dup3", name) == 0) return SYS_dup3;
#endif /* SYS_dup3 */
#ifdef SYS_epoll_create
if(strcmp("SYS_epoll_create", name) == 0) return SYS_epoll_create;
#endif /* SYS_epoll_create */
#ifdef SYS_epoll_create1
if(strcmp("SYS_epoll_create1", name) == 0) return SYS_epoll_create1;
#endif /* SYS_epoll_create1 */
#ifdef SYS_epoll_ctl
if(strcmp("SYS_epoll_ctl", name) == 0) return SYS_epoll_ctl;
#endif /* SYS_epoll_ctl */
#ifdef SYS_epoll_pwait
if(strcmp("SYS_epoll_pwait", name) == 0) return SYS_epoll_pwait;
#endif /* SYS_epoll_pwait */
#ifdef SYS_epoll_wait
if(strcmp("SYS_epoll_wait", name) == 0) return SYS_epoll_wait;
#endif /* SYS_epoll_wait */
#ifdef SYS_eventfd
if(strcmp("SYS_eventfd", name) == 0) return SYS_eventfd;
#endif /* SYS_eventfd */
#ifdef SYS_eventfd2
if(strcmp("SYS_eventfd2", name) == 0) return SYS_eventfd2;
#endif /* SYS_eventfd2 */
#ifdef SYS_execve
if(strcmp("SYS_execve", name) == 0) return SYS_execve;
#endif /* SYS_execve */
#ifdef SYS_exit
if(strcmp("SYS_exit", name) == 0) return SYS_exit;
#endif /* SYS_exit */
#ifdef SYS_exit_group
if(strcmp("SYS_exit_group", name) == 0) return SYS_exit_group;
#endif /* SYS_exit_group */
#ifdef SYS_faccessat
if(strcmp("SYS_faccessat", name) == 0) return SYS_faccessat;
#endif /* SYS_faccessat */
#ifdef SYS_fadvise64
if(strcmp("SYS_fadvise64", name) == 0) return SYS_fadvise64;
#endif /* SYS_fadvise64 */
#ifdef SYS_fadvise64_64
if(strcmp("SYS_fadvise64_64", name) == 0) return SYS_fadvise64_64;
#endif /* SYS_fadvise64_64 */
#ifdef SYS_fallocate
if(strcmp("SYS_fallocate", name) == 0) return SYS_fallocate;
#endif /* SYS_fallocate */
#ifdef SYS_fanotify_init
if(strcmp("SYS_fanotify_init", name) == 0) return SYS_fanotify_init;
#endif /* SYS_fanotify_init */
#ifdef SYS_fanotify_mark
if(strcmp("SYS_fanotify_mark", name) == 0) return SYS_fanotify_mark;
#endif /* SYS_fanotify_mark */
#ifdef SYS_fchdir
if(strcmp("SYS_fchdir", name) == 0) return SYS_fchdir;
#endif /* SYS_fchdir */
#ifdef SYS_fchmod
if(strcmp("SYS_fchmod", name) == 0) return SYS_fchmod;
#endif /* SYS_fchmod */
#ifdef SYS_fchmodat
if(strcmp("SYS_fchmodat", name) == 0) return SYS_fchmodat;
#endif /* SYS_fchmodat */
#ifdef SYS_fchown
if(strcmp("SYS_fchown", name) == 0) return SYS_fchown;
#endif /* SYS_fchown */
#ifdef SYS_fchown32
if(strcmp("SYS_fchown32", name) == 0) return SYS_fchown32;
#endif /* SYS_fchown32 */
#ifdef SYS_fchownat
if(strcmp("SYS_fchownat", name) == 0) return SYS_fchownat;
#endif /* SYS_fchownat */
#ifdef SYS_fcntl
if(strcmp("SYS_fcntl", name) == 0) return SYS_fcntl;
#endif /* SYS_fcntl */
#ifdef SYS_fcntl64
if(strcmp("SYS_fcntl64", name) == 0) return SYS_fcntl64;
#endif /* SYS_fcntl64 */
#ifdef SYS_fdatasync
if(strcmp("SYS_fdatasync", name) == 0) return SYS_fdatasync;
#endif /* SYS_fdatasync */
#ifdef SYS_fgetxattr
if(strcmp("SYS_fgetxattr", name) == 0) return SYS_fgetxattr;
#endif /* SYS_fgetxattr */
#ifdef SYS_finit_module
if(strcmp("SYS_finit_module", name) == 0) return SYS_finit_module;
#endif /* SYS_finit_module */
#ifdef SYS_flistxattr
if(strcmp("SYS_flistxattr", name) == 0) return SYS_flistxattr;
#endif /* SYS_flistxattr */
#ifdef SYS_flock
if(strcmp("SYS_flock", name) == 0) return SYS_flock;
#endif /* SYS_flock */
#ifdef SYS_fork
if(strcmp("SYS_fork", name) == 0) return SYS_fork;
#endif /* SYS_fork */
#ifdef SYS_fremovexattr
if(strcmp("SYS_fremovexattr", name) == 0) return SYS_fremovexattr;
#endif /* SYS_fremovexattr */
#ifdef SYS_fsetxattr
if(strcmp("SYS_fsetxattr", name) == 0) return SYS_fsetxattr;
#endif /* SYS_fsetxattr */
#ifdef SYS_fstat
if(strcmp("SYS_fstat", name) == 0) return SYS_fstat;
#endif /* SYS_fstat */
#ifdef SYS_fstat64
if(strcmp("SYS_fstat64", name) == 0) return SYS_fstat64;
#endif /* SYS_fstat64 */
#ifdef SYS_fstatat64
if(strcmp("SYS_fstatat64", name) == 0) return SYS_fstatat64;
#endif /* SYS_fstatat64 */
#ifdef SYS_fstatfs
if(strcmp("SYS_fstatfs", name) == 0) return SYS_fstatfs;
#endif /* SYS_fstatfs */
#ifdef SYS_fstatfs64
if(strcmp("SYS_fstatfs64", name) == 0) return SYS_fstatfs64;
#endif /* SYS_fstatfs64 */
#ifdef SYS_fsync
if(strcmp("SYS_fsync", name) == 0) return SYS_fsync;
#endif /* SYS_fsync */
#ifdef SYS_ftime
if(strcmp("SYS_ftime", name) == 0) return SYS_ftime;
#endif /* SYS_ftime */
#ifdef SYS_ftruncate
if(strcmp("SYS_ftruncate", name) == 0) return SYS_ftruncate;
#endif /* SYS_ftruncate */
#ifdef SYS_ftruncate64
if(strcmp("SYS_ftruncate64", name) == 0) return SYS_ftruncate64;
#endif /* SYS_ftruncate64 */
#ifdef SYS_futex
if(strcmp("SYS_futex", name) == 0) return SYS_futex;
#endif /* SYS_futex */
#ifdef SYS_futimesat
if(strcmp("SYS_futimesat", name) == 0) return SYS_futimesat;
#endif /* SYS_futimesat */
#ifdef SYS_get_kernel_syms
if(strcmp("SYS_get_kernel_syms", name) == 0) return SYS_get_kernel_syms;
#endif /* SYS_get_kernel_syms */
#ifdef SYS_get_mempolicy
if(strcmp("SYS_get_mempolicy", name) == 0) return SYS_get_mempolicy;
#endif /* SYS_get_mempolicy */
#ifdef SYS_get_robust_list
if(strcmp("SYS_get_robust_list", name) == 0) return SYS_get_robust_list;
#endif /* SYS_get_robust_list */
#ifdef SYS_get_thread_area
if(strcmp("SYS_get_thread_area", name) == 0) return SYS_get_thread_area;
#endif /* SYS_get_thread_area */
#ifdef SYS_getcpu
if(strcmp("SYS_getcpu", name) == 0) return SYS_getcpu;
#endif /* SYS_getcpu */
#ifdef SYS_getcwd
if(strcmp("SYS_getcwd", name) == 0) return SYS_getcwd;
#endif /* SYS_getcwd */
#ifdef SYS_getdents
if(strcmp("SYS_getdents", name) == 0) return SYS_getdents;
#endif /* SYS_getdents */
#ifdef SYS_getdents64
if(strcmp("SYS_getdents64", name) == 0) return SYS_getdents64;
#endif /* SYS_getdents64 */
#ifdef SYS_getegid
if(strcmp("SYS_getegid", name) == 0) return SYS_getegid;
#endif /* SYS_getegid */
#ifdef SYS_getegid32
if(strcmp("SYS_getegid32", name) == 0) return SYS_getegid32;
#endif /* SYS_getegid32 */
#ifdef SYS_geteuid
if(strcmp("SYS_geteuid", name) == 0) return SYS_geteuid;
#endif /* SYS_geteuid */
#ifdef SYS_geteuid32
if(strcmp("SYS_geteuid32", name) == 0) return SYS_geteuid32;
#endif /* SYS_geteuid32 */
#ifdef SYS_getgid
if(strcmp("SYS_getgid", name) == 0) return SYS_getgid;
#endif /* SYS_getgid */
#ifdef SYS_getgid32
if(strcmp("SYS_getgid32", name) == 0) return SYS_getgid32;
#endif /* SYS_getgid32 */
#ifdef SYS_getgroups
if(strcmp("SYS_getgroups", name) == 0) return SYS_getgroups;
#endif /* SYS_getgroups */
#ifdef SYS_getgroups32
if(strcmp("SYS_getgroups32", name) == 0) return SYS_getgroups32;
#endif /* SYS_getgroups32 */
#ifdef SYS_getitimer
if(strcmp("SYS_getitimer", name) == 0) return SYS_getitimer;
#endif /* SYS_getitimer */
#ifdef SYS_getpgid
if(strcmp("SYS_getpgid", name) == 0) return SYS_getpgid;
#endif /* SYS_getpgid */
#ifdef SYS_getpgrp
if(strcmp("SYS_getpgrp", name) == 0) return SYS_getpgrp;
#endif /* SYS_getpgrp */
#ifdef SYS_getpid
if(strcmp("SYS_getpid", name) == 0) return SYS_getpid;
#endif /* SYS_getpid */
#ifdef SYS_getpmsg
if(strcmp("SYS_getpmsg", name) == 0) return SYS_getpmsg;
#endif /* SYS_getpmsg */
#ifdef SYS_getppid
if(strcmp("SYS_getppid", name) == 0) return SYS_getppid;
#endif /* SYS_getppid */
#ifdef SYS_getpriority
if(strcmp("SYS_getpriority", name) == 0) return SYS_getpriority;
#endif /* SYS_getpriority */
#ifdef SYS_getresgid
if(strcmp("SYS_getresgid", name) == 0) return SYS_getresgid;
#endif /* SYS_getresgid */
#ifdef SYS_getresgid32
if(strcmp("SYS_getresgid32", name) == 0) return SYS_getresgid32;
#endif /* SYS_getresgid32 */
#ifdef SYS_getresuid
if(strcmp("SYS_getresuid", name) == 0) return SYS_getresuid;
#endif /* SYS_getresuid */
#ifdef SYS_getresuid32
if(strcmp("SYS_getresuid32", name) == 0) return SYS_getresuid32;
#endif /* SYS_getresuid32 */
#ifdef SYS_getrlimit
if(strcmp("SYS_getrlimit", name) == 0) return SYS_getrlimit;
#endif /* SYS_getrlimit */
#ifdef SYS_getrusage
if(strcmp("SYS_getrusage", name) == 0) return SYS_getrusage;
#endif /* SYS_getrusage */
#ifdef SYS_getsid
if(strcmp("SYS_getsid", name) == 0) return SYS_getsid;
#endif /* SYS_getsid */
#ifdef SYS_gettid
if(strcmp("SYS_gettid", name) == 0) return SYS_gettid;
#endif /* SYS_gettid */
#ifdef SYS_gettimeofday
if(strcmp("SYS_gettimeofday", name) == 0) return SYS_gettimeofday;
#endif /* SYS_gettimeofday */
#ifdef SYS_getuid
if(strcmp("SYS_getuid", name) == 0) return SYS_getuid;
#endif /* SYS_getuid */
#ifdef SYS_getuid32
if(strcmp("SYS_getuid32", name) == 0) return SYS_getuid32;
#endif /* SYS_getuid32 */
#ifdef SYS_getxattr
if(strcmp("SYS_getxattr", name) == 0) return SYS_getxattr;
#endif /* SYS_getxattr */
#ifdef SYS_gtty
if(strcmp("SYS_gtty", name) == 0) return SYS_gtty;
#endif /* SYS_gtty */
#ifdef SYS_idle
if(strcmp("SYS_idle", name) == 0) return SYS_idle;
#endif /* SYS_idle */
#ifdef SYS_init_module
if(strcmp("SYS_init_module", name) == 0) return SYS_init_module;
#endif /* SYS_init_module */
#ifdef SYS_inotify_add_watch
if(strcmp("SYS_inotify_add_watch", name) == 0) return SYS_inotify_add_watch;
#endif /* SYS_inotify_add_watch */
#ifdef SYS_inotify_init
if(strcmp("SYS_inotify_init", name) == 0) return SYS_inotify_init;
#endif /* SYS_inotify_init */
#ifdef SYS_inotify_init1
if(strcmp("SYS_inotify_init1", name) == 0) return SYS_inotify_init1;
#endif /* SYS_inotify_init1 */
#ifdef SYS_inotify_rm_watch
if(strcmp("SYS_inotify_rm_watch", name) == 0) return SYS_inotify_rm_watch;
#endif /* SYS_inotify_rm_watch */
#ifdef SYS_io_cancel
if(strcmp("SYS_io_cancel", name) == 0) return SYS_io_cancel;
#endif /* SYS_io_cancel */
#ifdef SYS_io_destroy
if(strcmp("SYS_io_destroy", name) == 0) return SYS_io_destroy;
#endif /* SYS_io_destroy */
#ifdef SYS_io_getevents
if(strcmp("SYS_io_getevents", name) == 0) return SYS_io_getevents;
#endif /* SYS_io_getevents */
#ifdef SYS_io_setup
if(strcmp("SYS_io_setup", name) == 0) return SYS_io_setup;
#endif /* SYS_io_setup */
#ifdef SYS_io_submit
if(strcmp("SYS_io_submit", name) == 0) return SYS_io_submit;
#endif /* SYS_io_submit */
#ifdef SYS_ioctl
if(strcmp("SYS_ioctl", name) == 0) return SYS_ioctl;
#endif /* SYS_ioctl */
#ifdef SYS_ioperm
if(strcmp("SYS_ioperm", name) == 0) return SYS_ioperm;
#endif /* SYS_ioperm */
#ifdef SYS_iopl
if(strcmp("SYS_iopl", name) == 0) return SYS_iopl;
#endif /* SYS_iopl */
#ifdef SYS_ioprio_get
if(strcmp("SYS_ioprio_get", name) == 0) return SYS_ioprio_get;
#endif /* SYS_ioprio_get */
#ifdef SYS_ioprio_set
if(strcmp("SYS_ioprio_set", name) == 0) return SYS_ioprio_set;
#endif /* SYS_ioprio_set */
#ifdef SYS_ipc
if(strcmp("SYS_ipc", name) == 0) return SYS_ipc;
#endif /* SYS_ipc */
#ifdef SYS_kcmp
if(strcmp("SYS_kcmp", name) == 0) return SYS_kcmp;
#endif /* SYS_kcmp */
#ifdef SYS_kexec_load
if(strcmp("SYS_kexec_load", name) == 0) return SYS_kexec_load;
#endif /* SYS_kexec_load */
#ifdef SYS_keyctl
if(strcmp("SYS_keyctl", name) == 0) return SYS_keyctl;
#endif /* SYS_keyctl */
#ifdef SYS_kill
if(strcmp("SYS_kill", name) == 0) return SYS_kill;
#endif /* SYS_kill */
#ifdef SYS_lchown
if(strcmp("SYS_lchown", name) == 0) return SYS_lchown;
#endif /* SYS_lchown */
#ifdef SYS_lchown32
if(strcmp("SYS_lchown32", name) == 0) return SYS_lchown32;
#endif /* SYS_lchown32 */
#ifdef SYS_lgetxattr
if(strcmp("SYS_lgetxattr", name) == 0) return SYS_lgetxattr;
#endif /* SYS_lgetxattr */
#ifdef SYS_link
if(strcmp("SYS_link", name) == 0) return SYS_link;
#endif /* SYS_link */
#ifdef SYS_linkat
if(strcmp("SYS_linkat", name) == 0) return SYS_linkat;
#endif /* SYS_linkat */
#ifdef SYS_listxattr
if(strcmp("SYS_listxattr", name) == 0) return SYS_listxattr;
#endif /* SYS_listxattr */
#ifdef SYS_llistxattr
if(strcmp("SYS_llistxattr", name) == 0) return SYS_llistxattr;
#endif /* SYS_llistxattr */
#ifdef SYS_lock
if(strcmp("SYS_lock", name) == 0) return SYS_lock;
#endif /* SYS_lock */
#ifdef SYS_lookup_dcookie
if(strcmp("SYS_lookup_dcookie", name) == 0) return SYS_lookup_dcookie;
#endif /* SYS_lookup_dcookie */
#ifdef SYS_lremovexattr
if(strcmp("SYS_lremovexattr", name) == 0) return SYS_lremovexattr;
#endif /* SYS_lremovexattr */
#ifdef SYS_lseek
if(strcmp("SYS_lseek", name) == 0) return SYS_lseek;
#endif /* SYS_lseek */
#ifdef SYS_lsetxattr
if(strcmp("SYS_lsetxattr", name) == 0) return SYS_lsetxattr;
#endif /* SYS_lsetxattr */
#ifdef SYS_lstat
if(strcmp("SYS_lstat", name) == 0) return SYS_lstat;
#endif /* SYS_lstat */
#ifdef SYS_lstat64
if(strcmp("SYS_lstat64", name) == 0) return SYS_lstat64;
#endif /* SYS_lstat64 */
#ifdef SYS_madvise
if(strcmp("SYS_madvise", name) == 0) return SYS_madvise;
#endif /* SYS_madvise */
#ifdef SYS_mbind
if(strcmp("SYS_mbind", name) == 0) return SYS_mbind;
#endif /* SYS_mbind */
#ifdef SYS_migrate_pages
if(strcmp("SYS_migrate_pages", name) == 0) return SYS_migrate_pages;
#endif /* SYS_migrate_pages */
#ifdef SYS_mincore
if(strcmp("SYS_mincore", name) == 0) return SYS_mincore;
#endif /* SYS_mincore */
#ifdef SYS_mkdir
if(strcmp("SYS_mkdir", name) == 0) return SYS_mkdir;
#endif /* SYS_mkdir */
#ifdef SYS_mkdirat
if(strcmp("SYS_mkdirat", name) == 0) return SYS_mkdirat;
#endif /* SYS_mkdirat */
#ifdef SYS_mknod
if(strcmp("SYS_mknod", name) == 0) return SYS_mknod;
#endif /* SYS_mknod */
#ifdef SYS_mknodat
if(strcmp("SYS_mknodat", name) == 0) return SYS_mknodat;
#endif /* SYS_mknodat */
#ifdef SYS_mlock
if(strcmp("SYS_mlock", name) == 0) return SYS_mlock;
#endif /* SYS_mlock */
#ifdef SYS_mlockall
if(strcmp("SYS_mlockall", name) == 0) return SYS_mlockall;
#endif /* SYS_mlockall */
#ifdef SYS_mmap
if(strcmp("SYS_mmap", name) == 0) return SYS_mmap;
#endif /* SYS_mmap */
#ifdef SYS_mmap2
if(strcmp("SYS_mmap2", name) == 0) return SYS_mmap2;
#endif /* SYS_mmap2 */
#ifdef SYS_modify_ldt
if(strcmp("SYS_modify_ldt", name) == 0) return SYS_modify_ldt;
#endif /* SYS_modify_ldt */
#ifdef SYS_mount
if(strcmp("SYS_mount", name) == 0) return SYS_mount;
#endif /* SYS_mount */
#ifdef SYS_move_pages
if(strcmp("SYS_move_pages", name) == 0) return SYS_move_pages;
#endif /* SYS_move_pages */
#ifdef SYS_mprotect
if(strcmp("SYS_mprotect", name) == 0) return SYS_mprotect;
#endif /* SYS_mprotect */
#ifdef SYS_mpx
if(strcmp("SYS_mpx", name) == 0) return SYS_mpx;
#endif /* SYS_mpx */
#ifdef SYS_mq_getsetattr
if(strcmp("SYS_mq_getsetattr", name) == 0) return SYS_mq_getsetattr;
#endif /* SYS_mq_getsetattr */
#ifdef SYS_mq_notify
if(strcmp("SYS_mq_notify", name) == 0) return SYS_mq_notify;
#endif /* SYS_mq_notify */
#ifdef SYS_mq_open
if(strcmp("SYS_mq_open", name) == 0) return SYS_mq_open;
#endif /* SYS_mq_open */
#ifdef SYS_mq_timedreceive
if(strcmp("SYS_mq_timedreceive", name) == 0) return SYS_mq_timedreceive;
#endif /* SYS_mq_timedreceive */
#ifdef SYS_mq_timedsend
if(strcmp("SYS_mq_timedsend", name) == 0) return SYS_mq_timedsend;
#endif /* SYS_mq_timedsend */
#ifdef SYS_mq_unlink
if(strcmp("SYS_mq_unlink", name) == 0) return SYS_mq_unlink;
#endif /* SYS_mq_unlink */
#ifdef SYS_mremap
if(strcmp("SYS_mremap", name) == 0) return SYS_mremap;
#endif /* SYS_mremap */
#ifdef SYS_msync
if(strcmp("SYS_msync", name) == 0) return SYS_msync;
#endif /* SYS_msync */
#ifdef SYS_munlock
if(strcmp("SYS_munlock", name) == 0) return SYS_munlock;
#endif /* SYS_munlock */
#ifdef SYS_munlockall
if(strcmp("SYS_munlockall", name) == 0) return SYS_munlockall;
#endif /* SYS_munlockall */
#ifdef SYS_munmap
if(strcmp("SYS_munmap", name) == 0) return SYS_munmap;
#endif /* SYS_munmap */
#ifdef SYS_name_to_handle_at
if(strcmp("SYS_name_to_handle_at", name) == 0) return SYS_name_to_handle_at;
#endif /* SYS_name_to_handle_at */
#ifdef SYS_nanosleep
if(strcmp("SYS_nanosleep", name) == 0) return SYS_nanosleep;
#endif /* SYS_nanosleep */
#ifdef SYS_nfsservctl
if(strcmp("SYS_nfsservctl", name) == 0) return SYS_nfsservctl;
#endif /* SYS_nfsservctl */
#ifdef SYS_nice
if(strcmp("SYS_nice", name) == 0) return SYS_nice;
#endif /* SYS_nice */
#ifdef SYS_oldfstat
if(strcmp("SYS_oldfstat", name) == 0) return SYS_oldfstat;
#endif /* SYS_oldfstat */
#ifdef SYS_oldlstat
if(strcmp("SYS_oldlstat", name) == 0) return SYS_oldlstat;
#endif /* SYS_oldlstat */
#ifdef SYS_oldolduname
if(strcmp("SYS_oldolduname", name) == 0) return SYS_oldolduname;
#endif /* SYS_oldolduname */
#ifdef SYS_oldstat
if(strcmp("SYS_oldstat", name) == 0) return SYS_oldstat;
#endif /* SYS_oldstat */
#ifdef SYS_olduname
if(strcmp("SYS_olduname", name) == 0) return SYS_olduname;
#endif /* SYS_olduname */
#ifdef SYS_open
if(strcmp("SYS_open", name) == 0) return SYS_open;
#endif /* SYS_open */
#ifdef SYS_open_by_handle_at
if(strcmp("SYS_open_by_handle_at", name) == 0) return SYS_open_by_handle_at;
#endif /* SYS_open_by_handle_at */
#ifdef SYS_openat
if(strcmp("SYS_openat", name) == 0) return SYS_openat;
#endif /* SYS_openat */
#ifdef SYS_pause
if(strcmp("SYS_pause", name) == 0) return SYS_pause;
#endif /* SYS_pause */
#ifdef SYS_perf_event_open
if(strcmp("SYS_perf_event_open", name) == 0) return SYS_perf_event_open;
#endif /* SYS_perf_event_open */
#ifdef SYS_personality
if(strcmp("SYS_personality", name) == 0) return SYS_personality;
#endif /* SYS_personality */
#ifdef SYS_pipe
if(strcmp("SYS_pipe", name) == 0) return SYS_pipe;
#endif /* SYS_pipe */
#ifdef SYS_pipe2
if(strcmp("SYS_pipe2", name) == 0) return SYS_pipe2;
#endif /* SYS_pipe2 */
#ifdef SYS_pivot_root
if(strcmp("SYS_pivot_root", name) == 0) return SYS_pivot_root;
#endif /* SYS_pivot_root */
#ifdef SYS_poll
if(strcmp("SYS_poll", name) == 0) return SYS_poll;
#endif /* SYS_poll */
#ifdef SYS_ppoll
if(strcmp("SYS_ppoll", name) == 0) return SYS_ppoll;
#endif /* SYS_ppoll */
#ifdef SYS_prctl
if(strcmp("SYS_prctl", name) == 0) return SYS_prctl;
#endif /* SYS_prctl */
#ifdef SYS_pread64
if(strcmp("SYS_pread64", name) == 0) return SYS_pread64;
#endif /* SYS_pread64 */
#ifdef SYS_preadv
if(strcmp("SYS_preadv", name) == 0) return SYS_preadv;
#endif /* SYS_preadv */
#ifdef SYS_prlimit64
if(strcmp("SYS_prlimit64", name) == 0) return SYS_prlimit64;
#endif /* SYS_prlimit64 */
#ifdef SYS_process_vm_readv
if(strcmp("SYS_process_vm_readv", name) == 0) return SYS_process_vm_readv;
#endif /* SYS_process_vm_readv */
#ifdef SYS_process_vm_writev
if(strcmp("SYS_process_vm_writev", name) == 0) return SYS_process_vm_writev;
#endif /* SYS_process_vm_writev */
#ifdef SYS_prof
if(strcmp("SYS_prof", name) == 0) return SYS_prof;
#endif /* SYS_prof */
#ifdef SYS_profil
if(strcmp("SYS_profil", name) == 0) return SYS_profil;
#endif /* SYS_profil */
#ifdef SYS_pselect6
if(strcmp("SYS_pselect6", name) == 0) return SYS_pselect6;
#endif /* SYS_pselect6 */
#ifdef SYS_ptrace
if(strcmp("SYS_ptrace", name) == 0) return SYS_ptrace;
#endif /* SYS_ptrace */
#ifdef SYS_putpmsg
if(strcmp("SYS_putpmsg", name) == 0) return SYS_putpmsg;
#endif /* SYS_putpmsg */
#ifdef SYS_pwrite64
if(strcmp("SYS_pwrite64", name) == 0) return SYS_pwrite64;
#endif /* SYS_pwrite64 */
#ifdef SYS_pwritev
if(strcmp("SYS_pwritev", name) == 0) return SYS_pwritev;
#endif /* SYS_pwritev */
#ifdef SYS_query_module
if(strcmp("SYS_query_module", name) == 0) return SYS_query_module;
#endif /* SYS_query_module */
#ifdef SYS_quotactl
if(strcmp("SYS_quotactl", name) == 0) return SYS_quotactl;
#endif /* SYS_quotactl */
#ifdef SYS_read
if(strcmp("SYS_read", name) == 0) return SYS_read;
#endif /* SYS_read */
#ifdef SYS_readahead
if(strcmp("SYS_readahead", name) == 0) return SYS_readahead;
#endif /* SYS_readahead */
#ifdef SYS_readdir
if(strcmp("SYS_readdir", name) == 0) return SYS_readdir;
#endif /* SYS_readdir */
#ifdef SYS_readlink
if(strcmp("SYS_readlink", name) == 0) return SYS_readlink;
#endif /* SYS_readlink */
#ifdef SYS_readlinkat
if(strcmp("SYS_readlinkat", name) == 0) return SYS_readlinkat;
#endif /* SYS_readlinkat */
#ifdef SYS_readv
if(strcmp("SYS_readv", name) == 0) return SYS_readv;
#endif /* SYS_readv */
#ifdef SYS_reboot
if(strcmp("SYS_reboot", name) == 0) return SYS_reboot;
#endif /* SYS_reboot */
#ifdef SYS_recvmmsg
if(strcmp("SYS_recvmmsg", name) == 0) return SYS_recvmmsg;
#endif /* SYS_recvmmsg */
#ifdef SYS_remap_file_pages
if(strcmp("SYS_remap_file_pages", name) == 0) return SYS_remap_file_pages;
#endif /* SYS_remap_file_pages */
#ifdef SYS_removexattr
if(strcmp("SYS_removexattr", name) == 0) return SYS_removexattr;
#endif /* SYS_removexattr */
#ifdef SYS_rename
if(strcmp("SYS_rename", name) == 0) return SYS_rename;
#endif /* SYS_rename */
#ifdef SYS_renameat
if(strcmp("SYS_renameat", name) == 0) return SYS_renameat;
#endif /* SYS_renameat */
#ifdef SYS_renameat2
if(strcmp("SYS_renameat2", name) == 0) return SYS_renameat2;
#endif /* SYS_renameat2 */
#ifdef SYS_request_key
if(strcmp("SYS_request_key", name) == 0) return SYS_request_key;
#endif /* SYS_request_key */
#ifdef SYS_restart_syscall
if(strcmp("SYS_restart_syscall", name) == 0) return SYS_restart_syscall;
#endif /* SYS_restart_syscall */
#ifdef SYS_rmdir
if(strcmp("SYS_rmdir", name) == 0) return SYS_rmdir;
#endif /* SYS_rmdir */
#ifdef SYS_rt_sigaction
if(strcmp("SYS_rt_sigaction", name) == 0) return SYS_rt_sigaction;
#endif /* SYS_rt_sigaction */
#ifdef SYS_rt_sigpending
if(strcmp("SYS_rt_sigpending", name) == 0) return SYS_rt_sigpending;
#endif /* SYS_rt_sigpending */
#ifdef SYS_rt_sigprocmask
if(strcmp("SYS_rt_sigprocmask", name) == 0) return SYS_rt_sigprocmask;
#endif /* SYS_rt_sigprocmask */
#ifdef SYS_rt_sigqueueinfo
if(strcmp("SYS_rt_sigqueueinfo", name) == 0) return SYS_rt_sigqueueinfo;
#endif /* SYS_rt_sigqueueinfo */
#ifdef SYS_rt_sigreturn
if(strcmp("SYS_rt_sigreturn", name) == 0) return SYS_rt_sigreturn;
#endif /* SYS_rt_sigreturn */
#ifdef SYS_rt_sigsuspend
if(strcmp("SYS_rt_sigsuspend", name) == 0) return SYS_rt_sigsuspend;
#endif /* SYS_rt_sigsuspend */
#ifdef SYS_rt_sigtimedwait
if(strcmp("SYS_rt_sigtimedwait", name) == 0) return SYS_rt_sigtimedwait;
#endif /* SYS_rt_sigtimedwait */
#ifdef SYS_rt_tgsigqueueinfo
if(strcmp("SYS_rt_tgsigqueueinfo", name) == 0) return SYS_rt_tgsigqueueinfo;
#endif /* SYS_rt_tgsigqueueinfo */
#ifdef SYS_sched_get_priority_max
if(strcmp("SYS_sched_get_priority_max", name) == 0) return SYS_sched_get_priority_max;
#endif /* SYS_sched_get_priority_max */
#ifdef SYS_sched_get_priority_min
if(strcmp("SYS_sched_get_priority_min", name) == 0) return SYS_sched_get_priority_min;
#endif /* SYS_sched_get_priority_min */
#ifdef SYS_sched_getaffinity
if(strcmp("SYS_sched_getaffinity", name) == 0) return SYS_sched_getaffinity;
#endif /* SYS_sched_getaffinity */
#ifdef SYS_sched_getattr
if(strcmp("SYS_sched_getattr", name) == 0) return SYS_sched_getattr;
#endif /* SYS_sched_getattr */
#ifdef SYS_sched_getparam
if(strcmp("SYS_sched_getparam", name) == 0) return SYS_sched_getparam;
#endif /* SYS_sched_getparam */
#ifdef SYS_sched_getscheduler
if(strcmp("SYS_sched_getscheduler", name) == 0) return SYS_sched_getscheduler;
#endif /* SYS_sched_getscheduler */
#ifdef SYS_sched_rr_get_interval
if(strcmp("SYS_sched_rr_get_interval", name) == 0) return SYS_sched_rr_get_interval;
#endif /* SYS_sched_rr_get_interval */
#ifdef SYS_sched_setaffinity
if(strcmp("SYS_sched_setaffinity", name) == 0) return SYS_sched_setaffinity;
#endif /* SYS_sched_setaffinity */
#ifdef SYS_sched_setattr
if(strcmp("SYS_sched_setattr", name) == 0) return SYS_sched_setattr;
#endif /* SYS_sched_setattr */
#ifdef SYS_sched_setparam
if(strcmp("SYS_sched_setparam", name) == 0) return SYS_sched_setparam;
#endif /* SYS_sched_setparam */
#ifdef SYS_sched_setscheduler
if(strcmp("SYS_sched_setscheduler", name) == 0) return SYS_sched_setscheduler;
#endif /* SYS_sched_setscheduler */
#ifdef SYS_sched_yield
if(strcmp("SYS_sched_yield", name) == 0) return SYS_sched_yield;
#endif /* SYS_sched_yield */
#ifdef SYS_seccomp
if(strcmp("SYS_seccomp", name) == 0) return SYS_seccomp;
#endif /* SYS_seccomp */
#ifdef SYS_select
if(strcmp("SYS_select", name) == 0) return SYS_select;
#endif /* SYS_select */
#ifdef SYS_sendfile
if(strcmp("SYS_sendfile", name) == 0) return SYS_sendfile;
#endif /* SYS_sendfile */
#ifdef SYS_sendfile64
if(strcmp("SYS_sendfile64", name) == 0) return SYS_sendfile64;
#endif /* SYS_sendfile64 */
#ifdef SYS_sendmmsg
if(strcmp("SYS_sendmmsg", name) == 0) return SYS_sendmmsg;
#endif /* SYS_sendmmsg */
#ifdef SYS_set_mempolicy
if(strcmp("SYS_set_mempolicy", name) == 0) return SYS_set_mempolicy;
#endif /* SYS_set_mempolicy */
#ifdef SYS_set_robust_list
if(strcmp("SYS_set_robust_list", name) == 0) return SYS_set_robust_list;
#endif /* SYS_set_robust_list */
#ifdef SYS_set_thread_area
if(strcmp("SYS_set_thread_area", name) == 0) return SYS_set_thread_area;
#endif /* SYS_set_thread_area */
#ifdef SYS_set_tid_address
if(strcmp("SYS_set_tid_address", name) == 0) return SYS_set_tid_address;
#endif /* SYS_set_tid_address */
#ifdef SYS_setdomainname
if(strcmp("SYS_setdomainname", name) == 0) return SYS_setdomainname;
#endif /* SYS_setdomainname */
#ifdef SYS_setfsgid
if(strcmp("SYS_setfsgid", name) == 0) return SYS_setfsgid;
#endif /* SYS_setfsgid */
#ifdef SYS_setfsgid32
if(strcmp("SYS_setfsgid32", name) == 0) return SYS_setfsgid32;
#endif /* SYS_setfsgid32 */
#ifdef SYS_setfsuid
if(strcmp("SYS_setfsuid", name) == 0) return SYS_setfsuid;
#endif /* SYS_setfsuid */
#ifdef SYS_setfsuid32
if(strcmp("SYS_setfsuid32", name) == 0) return SYS_setfsuid32;
#endif /* SYS_setfsuid32 */
#ifdef SYS_setgid
if(strcmp("SYS_setgid", name) == 0) return SYS_setgid;
#endif /* SYS_setgid */
#ifdef SYS_setgid32
if(strcmp("SYS_setgid32", name) == 0) return SYS_setgid32;
#endif /* SYS_setgid32 */
#ifdef SYS_setgroups
if(strcmp("SYS_setgroups", name) == 0) return SYS_setgroups;
#endif /* SYS_setgroups */
#ifdef SYS_setgroups32
if(strcmp("SYS_setgroups32", name) == 0) return SYS_setgroups32;
#endif /* SYS_setgroups32 */
#ifdef SYS_sethostname
if(strcmp("SYS_sethostname", name) == 0) return SYS_sethostname;
#endif /* SYS_sethostname */
#ifdef SYS_setitimer
if(strcmp("SYS_setitimer", name) == 0) return SYS_setitimer;
#endif /* SYS_setitimer */
#ifdef SYS_setns
if(strcmp("SYS_setns", name) == 0) return SYS_setns;
#endif /* SYS_setns */
#ifdef SYS_setpgid
if(strcmp("SYS_setpgid", name) == 0) return SYS_setpgid;
#endif /* SYS_setpgid */
#ifdef SYS_setpriority
if(strcmp("SYS_setpriority", name) == 0) return SYS_setpriority;
#endif /* SYS_setpriority */
#ifdef SYS_setregid
if(strcmp("SYS_setregid", name) == 0) return SYS_setregid;
#endif /* SYS_setregid */
#ifdef SYS_setregid32
if(strcmp("SYS_setregid32", name) == 0) return SYS_setregid32;
#endif /* SYS_setregid32 */
#ifdef SYS_setresgid
if(strcmp("SYS_setresgid", name) == 0) return SYS_setresgid;
#endif /* SYS_setresgid */
#ifdef SYS_setresgid32
if(strcmp("SYS_setresgid32", name) == 0) return SYS_setresgid32;
#endif /* SYS_setresgid32 */
#ifdef SYS_setresuid
if(strcmp("SYS_setresuid", name) == 0) return SYS_setresuid;
#endif /* SYS_setresuid */
#ifdef SYS_setresuid32
if(strcmp("SYS_setresuid32", name) == 0) return SYS_setresuid32;
#endif /* SYS_setresuid32 */
#ifdef SYS_setreuid
if(strcmp("SYS_setreuid", name) == 0) return SYS_setreuid;
#endif /* SYS_setreuid */
#ifdef SYS_setreuid32
if(strcmp("SYS_setreuid32", name) == 0) return SYS_setreuid32;
#endif /* SYS_setreuid32 */
#ifdef SYS_setrlimit
if(strcmp("SYS_setrlimit", name) == 0) return SYS_setrlimit;
#endif /* SYS_setrlimit */
#ifdef SYS_setsid
if(strcmp("SYS_setsid", name) == 0) return SYS_setsid;
#endif /* SYS_setsid */
#ifdef SYS_settimeofday
if(strcmp("SYS_settimeofday", name) == 0) return SYS_settimeofday;
#endif /* SYS_settimeofday */
#ifdef SYS_setuid
if(strcmp("SYS_setuid", name) == 0) return SYS_setuid;
#endif /* SYS_setuid */
#ifdef SYS_setuid32
if(strcmp("SYS_setuid32", name) == 0) return SYS_setuid32;
#endif /* SYS_setuid32 */
#ifdef SYS_setxattr
if(strcmp("SYS_setxattr", name) == 0) return SYS_setxattr;
#endif /* SYS_setxattr */
#ifdef SYS_sgetmask
if(strcmp("SYS_sgetmask", name) == 0) return SYS_sgetmask;
#endif /* SYS_sgetmask */
#ifdef SYS_sigaction
if(strcmp("SYS_sigaction", name) == 0) return SYS_sigaction;
#endif /* SYS_sigaction */
#ifdef SYS_sigaltstack
if(strcmp("SYS_sigaltstack", name) == 0) return SYS_sigaltstack;
#endif /* SYS_sigaltstack */
#ifdef SYS_signal
if(strcmp("SYS_signal", name) == 0) return SYS_signal;
#endif /* SYS_signal */
#ifdef SYS_signalfd
if(strcmp("SYS_signalfd", name) == 0) return SYS_signalfd;
#endif /* SYS_signalfd */
#ifdef SYS_signalfd4
if(strcmp("SYS_signalfd4", name) == 0) return SYS_signalfd4;
#endif /* SYS_signalfd4 */
#ifdef SYS_sigpending
if(strcmp("SYS_sigpending", name) == 0) return SYS_sigpending;
#endif /* SYS_sigpending */
#ifdef SYS_sigprocmask
if(strcmp("SYS_sigprocmask", name) == 0) return SYS_sigprocmask;
#endif /* SYS_sigprocmask */
#ifdef SYS_sigreturn
if(strcmp("SYS_sigreturn", name) == 0) return SYS_sigreturn;
#endif /* SYS_sigreturn */
#ifdef SYS_sigsuspend
if(strcmp("SYS_sigsuspend", name) == 0) return SYS_sigsuspend;
#endif /* SYS_sigsuspend */
#ifdef SYS_socketcall
if(strcmp("SYS_socketcall", name) == 0) return SYS_socketcall;
#endif /* SYS_socketcall */
#ifdef SYS_splice
if(strcmp("SYS_splice", name) == 0) return SYS_splice;
#endif /* SYS_splice */
#ifdef SYS_ssetmask
if(strcmp("SYS_ssetmask", name) == 0) return SYS_ssetmask;
#endif /* SYS_ssetmask */
#ifdef SYS_stat
if(strcmp("SYS_stat", name) == 0) return SYS_stat;
#endif /* SYS_stat */
#ifdef SYS_stat64
if(strcmp("SYS_stat64", name) == 0) return SYS_stat64;
#endif /* SYS_stat64 */
#ifdef SYS_statfs
if(strcmp("SYS_statfs", name) == 0) return SYS_statfs;
#endif /* SYS_statfs */
#ifdef SYS_statfs64
if(strcmp("SYS_statfs64", name) == 0) return SYS_statfs64;
#endif /* SYS_statfs64 */
#ifdef SYS_stime
if(strcmp("SYS_stime", name) == 0) return SYS_stime;
#endif /* SYS_stime */
#ifdef SYS_stty
if(strcmp("SYS_stty", name) == 0) return SYS_stty;
#endif /* SYS_stty */
#ifdef SYS_swapoff
if(strcmp("SYS_swapoff", name) == 0) return SYS_swapoff;
#endif /* SYS_swapoff */
#ifdef SYS_swapon
if(strcmp("SYS_swapon", name) == 0) return SYS_swapon;
#endif /* SYS_swapon */
#ifdef SYS_symlink
if(strcmp("SYS_symlink", name) == 0) return SYS_symlink;
#endif /* SYS_symlink */
#ifdef SYS_symlinkat
if(strcmp("SYS_symlinkat", name) == 0) return SYS_symlinkat;
#endif /* SYS_symlinkat */
#ifdef SYS_sync
if(strcmp("SYS_sync", name) == 0) return SYS_sync;
#endif /* SYS_sync */
#ifdef SYS_sync_file_range
if(strcmp("SYS_sync_file_range", name) == 0) return SYS_sync_file_range;
#endif /* SYS_sync_file_range */
#ifdef SYS_syncfs
if(strcmp("SYS_syncfs", name) == 0) return SYS_syncfs;
#endif /* SYS_syncfs */
#ifdef SYS_sysfs
if(strcmp("SYS_sysfs", name) == 0) return SYS_sysfs;
#endif /* SYS_sysfs */
#ifdef SYS_sysinfo
if(strcmp("SYS_sysinfo", name) == 0) return SYS_sysinfo;
#endif /* SYS_sysinfo */
#ifdef SYS_syslog
if(strcmp("SYS_syslog", name) == 0) return SYS_syslog;
#endif /* SYS_syslog */
#ifdef SYS_tee
if(strcmp("SYS_tee", name) == 0) return SYS_tee;
#endif /* SYS_tee */
#ifdef SYS_tgkill
if(strcmp("SYS_tgkill", name) == 0) return SYS_tgkill;
#endif /* SYS_tgkill */
#ifdef SYS_time
if(strcmp("SYS_time", name) == 0) return SYS_time;
#endif /* SYS_time */
#ifdef SYS_timer_create
if(strcmp("SYS_timer_create", name) == 0) return SYS_timer_create;
#endif /* SYS_timer_create */
#ifdef SYS_timer_delete
if(strcmp("SYS_timer_delete", name) == 0) return SYS_timer_delete;
#endif /* SYS_timer_delete */
#ifdef SYS_timer_getoverrun
if(strcmp("SYS_timer_getoverrun", name) == 0) return SYS_timer_getoverrun;
#endif /* SYS_timer_getoverrun */
#ifdef SYS_timer_gettime
if(strcmp("SYS_timer_gettime", name) == 0) return SYS_timer_gettime;
#endif /* SYS_timer_gettime */
#ifdef SYS_timer_settime
if(strcmp("SYS_timer_settime", name) == 0) return SYS_timer_settime;
#endif /* SYS_timer_settime */
#ifdef SYS_timerfd_create
if(strcmp("SYS_timerfd_create", name) == 0) return SYS_timerfd_create;
#endif /* SYS_timerfd_create */
#ifdef SYS_timerfd_gettime
if(strcmp("SYS_timerfd_gettime", name) == 0) return SYS_timerfd_gettime;
#endif /* SYS_timerfd_gettime */
#ifdef SYS_timerfd_settime
if(strcmp("SYS_timerfd_settime", name) == 0) return SYS_timerfd_settime;
#endif /* SYS_timerfd_settime */
#ifdef SYS_times
if(strcmp("SYS_times", name) == 0) return SYS_times;
#endif /* SYS_times */
#ifdef SYS_tkill
if(strcmp("SYS_tkill", name) == 0) return SYS_tkill;
#endif /* SYS_tkill */
#ifdef SYS_truncate
if(strcmp("SYS_truncate", name) == 0) return SYS_truncate;
#endif /* SYS_truncate */
#ifdef SYS_truncate64
if(strcmp("SYS_truncate64", name) == 0) return SYS_truncate64;
#endif /* SYS_truncate64 */
#ifdef SYS_ugetrlimit
if(strcmp("SYS_ugetrlimit", name) == 0) return SYS_ugetrlimit;
#endif /* SYS_ugetrlimit */
#ifdef SYS_ulimit
if(strcmp("SYS_ulimit", name) == 0) return SYS_ulimit;
#endif /* SYS_ulimit */
#ifdef SYS_umask
if(strcmp("SYS_umask", name) == 0) return SYS_umask;
#endif /* SYS_umask */
#ifdef SYS_umount
if(strcmp("SYS_umount", name) == 0) return SYS_umount;
#endif /* SYS_umount */
#ifdef SYS_umount2
if(strcmp("SYS_umount2", name) == 0) return SYS_umount2;
#endif /* SYS_umount2 */
#ifdef SYS_uname
if(strcmp("SYS_uname", name) == 0) return SYS_uname;
#endif /* SYS_uname */
#ifdef SYS_unlink
if(strcmp("SYS_unlink", name) == 0) return SYS_unlink;
#endif /* SYS_unlink */
#ifdef SYS_unlinkat
if(strcmp("SYS_unlinkat", name) == 0) return SYS_unlinkat;
#endif /* SYS_unlinkat */
#ifdef SYS_unshare
if(strcmp("SYS_unshare", name) == 0) return SYS_unshare;
#endif /* SYS_unshare */
#ifdef SYS_uselib
if(strcmp("SYS_uselib", name) == 0) return SYS_uselib;
#endif /* SYS_uselib */
#ifdef SYS_ustat
if(strcmp("SYS_ustat", name) == 0) return SYS_ustat;
#endif /* SYS_ustat */
#ifdef SYS_utime
if(strcmp("SYS_utime", name) == 0) return SYS_utime;
#endif /* SYS_utime */
#ifdef SYS_utimensat
if(strcmp("SYS_utimensat", name) == 0) return SYS_utimensat;
#endif /* SYS_utimensat */
#ifdef SYS_utimes
if(strcmp("SYS_utimes", name) == 0) return SYS_utimes;
#endif /* SYS_utimes */
#ifdef SYS_vfork
if(strcmp("SYS_vfork", name) == 0) return SYS_vfork;
#endif /* SYS_vfork */
#ifdef SYS_vhangup
if(strcmp("SYS_vhangup", name) == 0) return SYS_vhangup;
#endif /* SYS_vhangup */
#ifdef SYS_vm86
if(strcmp("SYS_vm86", name) == 0) return SYS_vm86;
#endif /* SYS_vm86 */
#ifdef SYS_vm86old
if(strcmp("SYS_vm86old", name) == 0) return SYS_vm86old;
#endif /* SYS_vm86old */
#ifdef SYS_vmsplice
if(strcmp("SYS_vmsplice", name) == 0) return SYS_vmsplice;
#endif /* SYS_vmsplice */
#ifdef SYS_vserver
if(strcmp("SYS_vserver", name) == 0) return SYS_vserver;
#endif /* SYS_vserver */
#ifdef SYS_wait4
if(strcmp("SYS_wait4", name) == 0) return SYS_wait4;
#endif /* SYS_wait4 */
#ifdef SYS_waitid
if(strcmp("SYS_waitid", name) == 0) return SYS_waitid;
#endif /* SYS_waitid */
#ifdef SYS_waitpid
if(strcmp("SYS_waitpid", name) == 0) return SYS_waitpid;
#endif /* SYS_waitpid */
#ifdef SYS_write
if(strcmp("SYS_write", name) == 0) return SYS_write;
#endif /* SYS_write */
#ifdef SYS_writev
if(strcmp("SYS_writev", name) == 0) return SYS_writev;
#endif /* SYS_writev */
#ifdef SYS__sysctl
if(strcmp("SYS__sysctl", name) == 0) return SYS__sysctl;
#endif /* SYS__sysctl */
#ifdef SYS_accept
if(strcmp("SYS_accept", name) == 0) return SYS_accept;
#endif /* SYS_accept */
#ifdef SYS_accept4
if(strcmp("SYS_accept4", name) == 0) return SYS_accept4;
#endif /* SYS_accept4 */
#ifdef SYS_access
if(strcmp("SYS_access", name) == 0) return SYS_access;
#endif /* SYS_access */
#ifdef SYS_acct
if(strcmp("SYS_acct", name) == 0) return SYS_acct;
#endif /* SYS_acct */
#ifdef SYS_add_key
if(strcmp("SYS_add_key", name) == 0) return SYS_add_key;
#endif /* SYS_add_key */
#ifdef SYS_adjtimex
if(strcmp("SYS_adjtimex", name) == 0) return SYS_adjtimex;
#endif /* SYS_adjtimex */
#ifdef SYS_afs_syscall
if(strcmp("SYS_afs_syscall", name) == 0) return SYS_afs_syscall;
#endif /* SYS_afs_syscall */
#ifdef SYS_alarm
if(strcmp("SYS_alarm", name) == 0) return SYS_alarm;
#endif /* SYS_alarm */
#ifdef SYS_arch_prctl
if(strcmp("SYS_arch_prctl", name) == 0) return SYS_arch_prctl;
#endif /* SYS_arch_prctl */
#ifdef SYS_bind
if(strcmp("SYS_bind", name) == 0) return SYS_bind;
#endif /* SYS_bind */
#ifdef SYS_brk
if(strcmp("SYS_brk", name) == 0) return SYS_brk;
#endif /* SYS_brk */
#ifdef SYS_capget
if(strcmp("SYS_capget", name) == 0) return SYS_capget;
#endif /* SYS_capget */
#ifdef SYS_capset
if(strcmp("SYS_capset", name) == 0) return SYS_capset;
#endif /* SYS_capset */
#ifdef SYS_chdir
if(strcmp("SYS_chdir", name) == 0) return SYS_chdir;
#endif /* SYS_chdir */
#ifdef SYS_chmod
if(strcmp("SYS_chmod", name) == 0) return SYS_chmod;
#endif /* SYS_chmod */
#ifdef SYS_chown
if(strcmp("SYS_chown", name) == 0) return SYS_chown;
#endif /* SYS_chown */
#ifdef SYS_chroot
if(strcmp("SYS_chroot", name) == 0) return SYS_chroot;
#endif /* SYS_chroot */
#ifdef SYS_clock_adjtime
if(strcmp("SYS_clock_adjtime", name) == 0) return SYS_clock_adjtime;
#endif /* SYS_clock_adjtime */
#ifdef SYS_clock_getres
if(strcmp("SYS_clock_getres", name) == 0) return SYS_clock_getres;
#endif /* SYS_clock_getres */
#ifdef SYS_clock_gettime
if(strcmp("SYS_clock_gettime", name) == 0) return SYS_clock_gettime;
#endif /* SYS_clock_gettime */
#ifdef SYS_clock_nanosleep
if(strcmp("SYS_clock_nanosleep", name) == 0) return SYS_clock_nanosleep;
#endif /* SYS_clock_nanosleep */
#ifdef SYS_clock_settime
if(strcmp("SYS_clock_settime", name) == 0) return SYS_clock_settime;
#endif /* SYS_clock_settime */
#ifdef SYS_clone
if(strcmp("SYS_clone", name) == 0) return SYS_clone;
#endif /* SYS_clone */
#ifdef SYS_close
if(strcmp("SYS_close", name) == 0) return SYS_close;
#endif /* SYS_close */
#ifdef SYS_connect
if(strcmp("SYS_connect", name) == 0) return SYS_connect;
#endif /* SYS_connect */
#ifdef SYS_creat
if(strcmp("SYS_creat", name) == 0) return SYS_creat;
#endif /* SYS_creat */
#ifdef SYS_create_module
if(strcmp("SYS_create_module", name) == 0) return SYS_create_module;
#endif /* SYS_create_module */
#ifdef SYS_delete_module
if(strcmp("SYS_delete_module", name) == 0) return SYS_delete_module;
#endif /* SYS_delete_module */
#ifdef SYS_dup
if(strcmp("SYS_dup", name) == 0) return SYS_dup;
#endif /* SYS_dup */
#ifdef SYS_dup2
if(strcmp("SYS_dup2", name) == 0) return SYS_dup2;
#endif /* SYS_dup2 */
#ifdef SYS_dup3
if(strcmp("SYS_dup3", name) == 0) return SYS_dup3;
#endif /* SYS_dup3 */
#ifdef SYS_epoll_create
if(strcmp("SYS_epoll_create", name) == 0) return SYS_epoll_create;
#endif /* SYS_epoll_create */
#ifdef SYS_epoll_create1
if(strcmp("SYS_epoll_create1", name) == 0) return SYS_epoll_create1;
#endif /* SYS_epoll_create1 */
#ifdef SYS_epoll_ctl
if(strcmp("SYS_epoll_ctl", name) == 0) return SYS_epoll_ctl;
#endif /* SYS_epoll_ctl */
#ifdef SYS_epoll_ctl_old
if(strcmp("SYS_epoll_ctl_old", name) == 0) return SYS_epoll_ctl_old;
#endif /* SYS_epoll_ctl_old */
#ifdef SYS_epoll_pwait
if(strcmp("SYS_epoll_pwait", name) == 0) return SYS_epoll_pwait;
#endif /* SYS_epoll_pwait */
#ifdef SYS_epoll_wait
if(strcmp("SYS_epoll_wait", name) == 0) return SYS_epoll_wait;
#endif /* SYS_epoll_wait */
#ifdef SYS_epoll_wait_old
if(strcmp("SYS_epoll_wait_old", name) == 0) return SYS_epoll_wait_old;
#endif /* SYS_epoll_wait_old */
#ifdef SYS_eventfd
if(strcmp("SYS_eventfd", name) == 0) return SYS_eventfd;
#endif /* SYS_eventfd */
#ifdef SYS_eventfd2
if(strcmp("SYS_eventfd2", name) == 0) return SYS_eventfd2;
#endif /* SYS_eventfd2 */
#ifdef SYS_execve
if(strcmp("SYS_execve", name) == 0) return SYS_execve;
#endif /* SYS_execve */
#ifdef SYS_exit
if(strcmp("SYS_exit", name) == 0) return SYS_exit;
#endif /* SYS_exit */
#ifdef SYS_exit_group
if(strcmp("SYS_exit_group", name) == 0) return SYS_exit_group;
#endif /* SYS_exit_group */
#ifdef SYS_faccessat
if(strcmp("SYS_faccessat", name) == 0) return SYS_faccessat;
#endif /* SYS_faccessat */
#ifdef SYS_fadvise64
if(strcmp("SYS_fadvise64", name) == 0) return SYS_fadvise64;
#endif /* SYS_fadvise64 */
#ifdef SYS_fallocate
if(strcmp("SYS_fallocate", name) == 0) return SYS_fallocate;
#endif /* SYS_fallocate */
#ifdef SYS_fanotify_init
if(strcmp("SYS_fanotify_init", name) == 0) return SYS_fanotify_init;
#endif /* SYS_fanotify_init */
#ifdef SYS_fanotify_mark
if(strcmp("SYS_fanotify_mark", name) == 0) return SYS_fanotify_mark;
#endif /* SYS_fanotify_mark */
#ifdef SYS_fchdir
if(strcmp("SYS_fchdir", name) == 0) return SYS_fchdir;
#endif /* SYS_fchdir */
#ifdef SYS_fchmod
if(strcmp("SYS_fchmod", name) == 0) return SYS_fchmod;
#endif /* SYS_fchmod */
#ifdef SYS_fchmodat
if(strcmp("SYS_fchmodat", name) == 0) return SYS_fchmodat;
#endif /* SYS_fchmodat */
#ifdef SYS_fchown
if(strcmp("SYS_fchown", name) == 0) return SYS_fchown;
#endif /* SYS_fchown */
#ifdef SYS_fchownat
if(strcmp("SYS_fchownat", name) == 0) return SYS_fchownat;
#endif /* SYS_fchownat */
#ifdef SYS_fcntl
if(strcmp("SYS_fcntl", name) == 0) return SYS_fcntl;
#endif /* SYS_fcntl */
#ifdef SYS_fdatasync
if(strcmp("SYS_fdatasync", name) == 0) return SYS_fdatasync;
#endif /* SYS_fdatasync */
#ifdef SYS_fgetxattr
if(strcmp("SYS_fgetxattr", name) == 0) return SYS_fgetxattr;
#endif /* SYS_fgetxattr */
#ifdef SYS_finit_module
if(strcmp("SYS_finit_module", name) == 0) return SYS_finit_module;
#endif /* SYS_finit_module */
#ifdef SYS_flistxattr
if(strcmp("SYS_flistxattr", name) == 0) return SYS_flistxattr;
#endif /* SYS_flistxattr */
#ifdef SYS_flock
if(strcmp("SYS_flock", name) == 0) return SYS_flock;
#endif /* SYS_flock */
#ifdef SYS_fork
if(strcmp("SYS_fork", name) == 0) return SYS_fork;
#endif /* SYS_fork */
#ifdef SYS_fremovexattr
if(strcmp("SYS_fremovexattr", name) == 0) return SYS_fremovexattr;
#endif /* SYS_fremovexattr */
#ifdef SYS_fsetxattr
if(strcmp("SYS_fsetxattr", name) == 0) return SYS_fsetxattr;
#endif /* SYS_fsetxattr */
#ifdef SYS_fstat
if(strcmp("SYS_fstat", name) == 0) return SYS_fstat;
#endif /* SYS_fstat */
#ifdef SYS_fstatfs
if(strcmp("SYS_fstatfs", name) == 0) return SYS_fstatfs;
#endif /* SYS_fstatfs */
#ifdef SYS_fsync
if(strcmp("SYS_fsync", name) == 0) return SYS_fsync;
#endif /* SYS_fsync */
#ifdef SYS_ftruncate
if(strcmp("SYS_ftruncate", name) == 0) return SYS_ftruncate;
#endif /* SYS_ftruncate */
#ifdef SYS_futex
if(strcmp("SYS_futex", name) == 0) return SYS_futex;
#endif /* SYS_futex */
#ifdef SYS_futimesat
if(strcmp("SYS_futimesat", name) == 0) return SYS_futimesat;
#endif /* SYS_futimesat */
#ifdef SYS_get_kernel_syms
if(strcmp("SYS_get_kernel_syms", name) == 0) return SYS_get_kernel_syms;
#endif /* SYS_get_kernel_syms */
#ifdef SYS_get_mempolicy
if(strcmp("SYS_get_mempolicy", name) == 0) return SYS_get_mempolicy;
#endif /* SYS_get_mempolicy */
#ifdef SYS_get_robust_list
if(strcmp("SYS_get_robust_list", name) == 0) return SYS_get_robust_list;
#endif /* SYS_get_robust_list */
#ifdef SYS_get_thread_area
if(strcmp("SYS_get_thread_area", name) == 0) return SYS_get_thread_area;
#endif /* SYS_get_thread_area */
#ifdef SYS_getcpu
if(strcmp("SYS_getcpu", name) == 0) return SYS_getcpu;
#endif /* SYS_getcpu */
#ifdef SYS_getcwd
if(strcmp("SYS_getcwd", name) == 0) return SYS_getcwd;
#endif /* SYS_getcwd */
#ifdef SYS_getdents
if(strcmp("SYS_getdents", name) == 0) return SYS_getdents;
#endif /* SYS_getdents */
#ifdef SYS_getdents64
if(strcmp("SYS_getdents64", name) == 0) return SYS_getdents64;
#endif /* SYS_getdents64 */
#ifdef SYS_getegid
if(strcmp("SYS_getegid", name) == 0) return SYS_getegid;
#endif /* SYS_getegid */
#ifdef SYS_geteuid
if(strcmp("SYS_geteuid", name) == 0) return SYS_geteuid;
#endif /* SYS_geteuid */
#ifdef SYS_getgid
if(strcmp("SYS_getgid", name) == 0) return SYS_getgid;
#endif /* SYS_getgid */
#ifdef SYS_getgroups
if(strcmp("SYS_getgroups", name) == 0) return SYS_getgroups;
#endif /* SYS_getgroups */
#ifdef SYS_getitimer
if(strcmp("SYS_getitimer", name) == 0) return SYS_getitimer;
#endif /* SYS_getitimer */
#ifdef SYS_getpeername
if(strcmp("SYS_getpeername", name) == 0) return SYS_getpeername;
#endif /* SYS_getpeername */
#ifdef SYS_getpgid
if(strcmp("SYS_getpgid", name) == 0) return SYS_getpgid;
#endif /* SYS_getpgid */
#ifdef SYS_getpgrp
if(strcmp("SYS_getpgrp", name) == 0) return SYS_getpgrp;
#endif /* SYS_getpgrp */
#ifdef SYS_getpid
if(strcmp("SYS_getpid", name) == 0) return SYS_getpid;
#endif /* SYS_getpid */
#ifdef SYS_getpmsg
if(strcmp("SYS_getpmsg", name) == 0) return SYS_getpmsg;
#endif /* SYS_getpmsg */
#ifdef SYS_getppid
if(strcmp("SYS_getppid", name) == 0) return SYS_getppid;
#endif /* SYS_getppid */
#ifdef SYS_getpriority
if(strcmp("SYS_getpriority", name) == 0) return SYS_getpriority;
#endif /* SYS_getpriority */
#ifdef SYS_getresgid
if(strcmp("SYS_getresgid", name) == 0) return SYS_getresgid;
#endif /* SYS_getresgid */
#ifdef SYS_getresuid
if(strcmp("SYS_getresuid", name) == 0) return SYS_getresuid;
#endif /* SYS_getresuid */
#ifdef SYS_getrlimit
if(strcmp("SYS_getrlimit", name) == 0) return SYS_getrlimit;
#endif /* SYS_getrlimit */
#ifdef SYS_getrusage
if(strcmp("SYS_getrusage", name) == 0) return SYS_getrusage;
#endif /* SYS_getrusage */
#ifdef SYS_getsid
if(strcmp("SYS_getsid", name) == 0) return SYS_getsid;
#endif /* SYS_getsid */
#ifdef SYS_getsockname
if(strcmp("SYS_getsockname", name) == 0) return SYS_getsockname;
#endif /* SYS_getsockname */
#ifdef SYS_getsockopt
if(strcmp("SYS_getsockopt", name) == 0) return SYS_getsockopt;
#endif /* SYS_getsockopt */
#ifdef SYS_gettid
if(strcmp("SYS_gettid", name) == 0) return SYS_gettid;
#endif /* SYS_gettid */
#ifdef SYS_gettimeofday
if(strcmp("SYS_gettimeofday", name) == 0) return SYS_gettimeofday;
#endif /* SYS_gettimeofday */
#ifdef SYS_getuid
if(strcmp("SYS_getuid", name) == 0) return SYS_getuid;
#endif /* SYS_getuid */
#ifdef SYS_getxattr
if(strcmp("SYS_getxattr", name) == 0) return SYS_getxattr;
#endif /* SYS_getxattr */
#ifdef SYS_init_module
if(strcmp("SYS_init_module", name) == 0) return SYS_init_module;
#endif /* SYS_init_module */
#ifdef SYS_inotify_add_watch
if(strcmp("SYS_inotify_add_watch", name) == 0) return SYS_inotify_add_watch;
#endif /* SYS_inotify_add_watch */
#ifdef SYS_inotify_init
if(strcmp("SYS_inotify_init", name) == 0) return SYS_inotify_init;
#endif /* SYS_inotify_init */
#ifdef SYS_inotify_init1
if(strcmp("SYS_inotify_init1", name) == 0) return SYS_inotify_init1;
#endif /* SYS_inotify_init1 */
#ifdef SYS_inotify_rm_watch
if(strcmp("SYS_inotify_rm_watch", name) == 0) return SYS_inotify_rm_watch;
#endif /* SYS_inotify_rm_watch */
#ifdef SYS_io_cancel
if(strcmp("SYS_io_cancel", name) == 0) return SYS_io_cancel;
#endif /* SYS_io_cancel */
#ifdef SYS_io_destroy
if(strcmp("SYS_io_destroy", name) == 0) return SYS_io_destroy;
#endif /* SYS_io_destroy */
#ifdef SYS_io_getevents
if(strcmp("SYS_io_getevents", name) == 0) return SYS_io_getevents;
#endif /* SYS_io_getevents */
#ifdef SYS_io_setup
if(strcmp("SYS_io_setup", name) == 0) return SYS_io_setup;
#endif /* SYS_io_setup */
#ifdef SYS_io_submit
if(strcmp("SYS_io_submit", name) == 0) return SYS_io_submit;
#endif /* SYS_io_submit */
#ifdef SYS_ioctl
if(strcmp("SYS_ioctl", name) == 0) return SYS_ioctl;
#endif /* SYS_ioctl */
#ifdef SYS_ioperm
if(strcmp("SYS_ioperm", name) == 0) return SYS_ioperm;
#endif /* SYS_ioperm */
#ifdef SYS_iopl
if(strcmp("SYS_iopl", name) == 0) return SYS_iopl;
#endif /* SYS_iopl */
#ifdef SYS_ioprio_get
if(strcmp("SYS_ioprio_get", name) == 0) return SYS_ioprio_get;
#endif /* SYS_ioprio_get */
#ifdef SYS_ioprio_set
if(strcmp("SYS_ioprio_set", name) == 0) return SYS_ioprio_set;
#endif /* SYS_ioprio_set */
#ifdef SYS_kcmp
if(strcmp("SYS_kcmp", name) == 0) return SYS_kcmp;
#endif /* SYS_kcmp */
#ifdef SYS_kexec_load
if(strcmp("SYS_kexec_load", name) == 0) return SYS_kexec_load;
#endif /* SYS_kexec_load */
#ifdef SYS_keyctl
if(strcmp("SYS_keyctl", name) == 0) return SYS_keyctl;
#endif /* SYS_keyctl */
#ifdef SYS_kill
if(strcmp("SYS_kill", name) == 0) return SYS_kill;
#endif /* SYS_kill */
#ifdef SYS_lchown
if(strcmp("SYS_lchown", name) == 0) return SYS_lchown;
#endif /* SYS_lchown */
#ifdef SYS_lgetxattr
if(strcmp("SYS_lgetxattr", name) == 0) return SYS_lgetxattr;
#endif /* SYS_lgetxattr */
#ifdef SYS_link
if(strcmp("SYS_link", name) == 0) return SYS_link;
#endif /* SYS_link */
#ifdef SYS_linkat
if(strcmp("SYS_linkat", name) == 0) return SYS_linkat;
#endif /* SYS_linkat */
#ifdef SYS_listen
if(strcmp("SYS_listen", name) == 0) return SYS_listen;
#endif /* SYS_listen */
#ifdef SYS_listxattr
if(strcmp("SYS_listxattr", name) == 0) return SYS_listxattr;
#endif /* SYS_listxattr */
#ifdef SYS_llistxattr
if(strcmp("SYS_llistxattr", name) == 0) return SYS_llistxattr;
#endif /* SYS_llistxattr */
#ifdef SYS_lookup_dcookie
if(strcmp("SYS_lookup_dcookie", name) == 0) return SYS_lookup_dcookie;
#endif /* SYS_lookup_dcookie */
#ifdef SYS_lremovexattr
if(strcmp("SYS_lremovexattr", name) == 0) return SYS_lremovexattr;
#endif /* SYS_lremovexattr */
#ifdef SYS_lseek
if(strcmp("SYS_lseek", name) == 0) return SYS_lseek;
#endif /* SYS_lseek */
#ifdef SYS_lsetxattr
if(strcmp("SYS_lsetxattr", name) == 0) return SYS_lsetxattr;
#endif /* SYS_lsetxattr */
#ifdef SYS_lstat
if(strcmp("SYS_lstat", name) == 0) return SYS_lstat;
#endif /* SYS_lstat */
#ifdef SYS_madvise
if(strcmp("SYS_madvise", name) == 0) return SYS_madvise;
#endif /* SYS_madvise */
#ifdef SYS_mbind
if(strcmp("SYS_mbind", name) == 0) return SYS_mbind;
#endif /* SYS_mbind */
#ifdef SYS_migrate_pages
if(strcmp("SYS_migrate_pages", name) == 0) return SYS_migrate_pages;
#endif /* SYS_migrate_pages */
#ifdef SYS_mincore
if(strcmp("SYS_mincore", name) == 0) return SYS_mincore;
#endif /* SYS_mincore */
#ifdef SYS_mkdir
if(strcmp("SYS_mkdir", name) == 0) return SYS_mkdir;
#endif /* SYS_mkdir */
#ifdef SYS_mkdirat
if(strcmp("SYS_mkdirat", name) == 0) return SYS_mkdirat;
#endif /* SYS_mkdirat */
#ifdef SYS_mknod
if(strcmp("SYS_mknod", name) == 0) return SYS_mknod;
#endif /* SYS_mknod */
#ifdef SYS_mknodat
if(strcmp("SYS_mknodat", name) == 0) return SYS_mknodat;
#endif /* SYS_mknodat */
#ifdef SYS_mlock
if(strcmp("SYS_mlock", name) == 0) return SYS_mlock;
#endif /* SYS_mlock */
#ifdef SYS_mlockall
if(strcmp("SYS_mlockall", name) == 0) return SYS_mlockall;
#endif /* SYS_mlockall */
#ifdef SYS_mmap
if(strcmp("SYS_mmap", name) == 0) return SYS_mmap;
#endif /* SYS_mmap */
#ifdef SYS_modify_ldt
if(strcmp("SYS_modify_ldt", name) == 0) return SYS_modify_ldt;
#endif /* SYS_modify_ldt */
#ifdef SYS_mount
if(strcmp("SYS_mount", name) == 0) return SYS_mount;
#endif /* SYS_mount */
#ifdef SYS_move_pages
if(strcmp("SYS_move_pages", name) == 0) return SYS_move_pages;
#endif /* SYS_move_pages */
#ifdef SYS_mprotect
if(strcmp("SYS_mprotect", name) == 0) return SYS_mprotect;
#endif /* SYS_mprotect */
#ifdef SYS_mq_getsetattr
if(strcmp("SYS_mq_getsetattr", name) == 0) return SYS_mq_getsetattr;
#endif /* SYS_mq_getsetattr */
#ifdef SYS_mq_notify
if(strcmp("SYS_mq_notify", name) == 0) return SYS_mq_notify;
#endif /* SYS_mq_notify */
#ifdef SYS_mq_open
if(strcmp("SYS_mq_open", name) == 0) return SYS_mq_open;
#endif /* SYS_mq_open */
#ifdef SYS_mq_timedreceive
if(strcmp("SYS_mq_timedreceive", name) == 0) return SYS_mq_timedreceive;
#endif /* SYS_mq_timedreceive */
#ifdef SYS_mq_timedsend
if(strcmp("SYS_mq_timedsend", name) == 0) return SYS_mq_timedsend;
#endif /* SYS_mq_timedsend */
#ifdef SYS_mq_unlink
if(strcmp("SYS_mq_unlink", name) == 0) return SYS_mq_unlink;
#endif /* SYS_mq_unlink */
#ifdef SYS_mremap
if(strcmp("SYS_mremap", name) == 0) return SYS_mremap;
#endif /* SYS_mremap */
#ifdef SYS_msgctl
if(strcmp("SYS_msgctl", name) == 0) return SYS_msgctl;
#endif /* SYS_msgctl */
#ifdef SYS_msgget
if(strcmp("SYS_msgget", name) == 0) return SYS_msgget;
#endif /* SYS_msgget */
#ifdef SYS_msgrcv
if(strcmp("SYS_msgrcv", name) == 0) return SYS_msgrcv;
#endif /* SYS_msgrcv */
#ifdef SYS_msgsnd
if(strcmp("SYS_msgsnd", name) == 0) return SYS_msgsnd;
#endif /* SYS_msgsnd */
#ifdef SYS_msync
if(strcmp("SYS_msync", name) == 0) return SYS_msync;
#endif /* SYS_msync */
#ifdef SYS_munlock
if(strcmp("SYS_munlock", name) == 0) return SYS_munlock;
#endif /* SYS_munlock */
#ifdef SYS_munlockall
if(strcmp("SYS_munlockall", name) == 0) return SYS_munlockall;
#endif /* SYS_munlockall */
#ifdef SYS_munmap
if(strcmp("SYS_munmap", name) == 0) return SYS_munmap;
#endif /* SYS_munmap */
#ifdef SYS_name_to_handle_at
if(strcmp("SYS_name_to_handle_at", name) == 0) return SYS_name_to_handle_at;
#endif /* SYS_name_to_handle_at */
#ifdef SYS_nanosleep
if(strcmp("SYS_nanosleep", name) == 0) return SYS_nanosleep;
#endif /* SYS_nanosleep */
#ifdef SYS_newfstatat
if(strcmp("SYS_newfstatat", name) == 0) return SYS_newfstatat;
#endif /* SYS_newfstatat */
#ifdef SYS_nfsservctl
if(strcmp("SYS_nfsservctl", name) == 0) return SYS_nfsservctl;
#endif /* SYS_nfsservctl */
#ifdef SYS_open
if(strcmp("SYS_open", name) == 0) return SYS_open;
#endif /* SYS_open */
#ifdef SYS_open_by_handle_at
if(strcmp("SYS_open_by_handle_at", name) == 0) return SYS_open_by_handle_at;
#endif /* SYS_open_by_handle_at */
#ifdef SYS_openat
if(strcmp("SYS_openat", name) == 0) return SYS_openat;
#endif /* SYS_openat */
#ifdef SYS_pause
if(strcmp("SYS_pause", name) == 0) return SYS_pause;
#endif /* SYS_pause */
#ifdef SYS_perf_event_open
if(strcmp("SYS_perf_event_open", name) == 0) return SYS_perf_event_open;
#endif /* SYS_perf_event_open */
#ifdef SYS_personality
if(strcmp("SYS_personality", name) == 0) return SYS_personality;
#endif /* SYS_personality */
#ifdef SYS_pipe
if(strcmp("SYS_pipe", name) == 0) return SYS_pipe;
#endif /* SYS_pipe */
#ifdef SYS_pipe2
if(strcmp("SYS_pipe2", name) == 0) return SYS_pipe2;
#endif /* SYS_pipe2 */
#ifdef SYS_pivot_root
if(strcmp("SYS_pivot_root", name) == 0) return SYS_pivot_root;
#endif /* SYS_pivot_root */
#ifdef SYS_poll
if(strcmp("SYS_poll", name) == 0) return SYS_poll;
#endif /* SYS_poll */
#ifdef SYS_ppoll
if(strcmp("SYS_ppoll", name) == 0) return SYS_ppoll;
#endif /* SYS_ppoll */
#ifdef SYS_prctl
if(strcmp("SYS_prctl", name) == 0) return SYS_prctl;
#endif /* SYS_prctl */
#ifdef SYS_pread64
if(strcmp("SYS_pread64", name) == 0) return SYS_pread64;
#endif /* SYS_pread64 */
#ifdef SYS_preadv
if(strcmp("SYS_preadv", name) == 0) return SYS_preadv;
#endif /* SYS_preadv */
#ifdef SYS_prlimit64
if(strcmp("SYS_prlimit64", name) == 0) return SYS_prlimit64;
#endif /* SYS_prlimit64 */
#ifdef SYS_process_vm_readv
if(strcmp("SYS_process_vm_readv", name) == 0) return SYS_process_vm_readv;
#endif /* SYS_process_vm_readv */
#ifdef SYS_process_vm_writev
if(strcmp("SYS_process_vm_writev", name) == 0) return SYS_process_vm_writev;
#endif /* SYS_process_vm_writev */
#ifdef SYS_pselect6
if(strcmp("SYS_pselect6", name) == 0) return SYS_pselect6;
#endif /* SYS_pselect6 */
#ifdef SYS_ptrace
if(strcmp("SYS_ptrace", name) == 0) return SYS_ptrace;
#endif /* SYS_ptrace */
#ifdef SYS_putpmsg
if(strcmp("SYS_putpmsg", name) == 0) return SYS_putpmsg;
#endif /* SYS_putpmsg */
#ifdef SYS_pwrite64
if(strcmp("SYS_pwrite64", name) == 0) return SYS_pwrite64;
#endif /* SYS_pwrite64 */
#ifdef SYS_pwritev
if(strcmp("SYS_pwritev", name) == 0) return SYS_pwritev;
#endif /* SYS_pwritev */
#ifdef SYS_query_module
if(strcmp("SYS_query_module", name) == 0) return SYS_query_module;
#endif /* SYS_query_module */
#ifdef SYS_quotactl
if(strcmp("SYS_quotactl", name) == 0) return SYS_quotactl;
#endif /* SYS_quotactl */
#ifdef SYS_read
if(strcmp("SYS_read", name) == 0) return SYS_read;
#endif /* SYS_read */
#ifdef SYS_readahead
if(strcmp("SYS_readahead", name) == 0) return SYS_readahead;
#endif /* SYS_readahead */
#ifdef SYS_readlink
if(strcmp("SYS_readlink", name) == 0) return SYS_readlink;
#endif /* SYS_readlink */
#ifdef SYS_readlinkat
if(strcmp("SYS_readlinkat", name) == 0) return SYS_readlinkat;
#endif /* SYS_readlinkat */
#ifdef SYS_readv
if(strcmp("SYS_readv", name) == 0) return SYS_readv;
#endif /* SYS_readv */
#ifdef SYS_reboot
if(strcmp("SYS_reboot", name) == 0) return SYS_reboot;
#endif /* SYS_reboot */
#ifdef SYS_recvfrom
if(strcmp("SYS_recvfrom", name) == 0) return SYS_recvfrom;
#endif /* SYS_recvfrom */
#ifdef SYS_recvmmsg
if(strcmp("SYS_recvmmsg", name) == 0) return SYS_recvmmsg;
#endif /* SYS_recvmmsg */
#ifdef SYS_recvmsg
if(strcmp("SYS_recvmsg", name) == 0) return SYS_recvmsg;
#endif /* SYS_recvmsg */
#ifdef SYS_remap_file_pages
if(strcmp("SYS_remap_file_pages", name) == 0) return SYS_remap_file_pages;
#endif /* SYS_remap_file_pages */
#ifdef SYS_removexattr
if(strcmp("SYS_removexattr", name) == 0) return SYS_removexattr;
#endif /* SYS_removexattr */
#ifdef SYS_rename
if(strcmp("SYS_rename", name) == 0) return SYS_rename;
#endif /* SYS_rename */
#ifdef SYS_renameat
if(strcmp("SYS_renameat", name) == 0) return SYS_renameat;
#endif /* SYS_renameat */
#ifdef SYS_renameat2
if(strcmp("SYS_renameat2", name) == 0) return SYS_renameat2;
#endif /* SYS_renameat2 */
#ifdef SYS_request_key
if(strcmp("SYS_request_key", name) == 0) return SYS_request_key;
#endif /* SYS_request_key */
#ifdef SYS_restart_syscall
if(strcmp("SYS_restart_syscall", name) == 0) return SYS_restart_syscall;
#endif /* SYS_restart_syscall */
#ifdef SYS_rmdir
if(strcmp("SYS_rmdir", name) == 0) return SYS_rmdir;
#endif /* SYS_rmdir */
#ifdef SYS_rt_sigaction
if(strcmp("SYS_rt_sigaction", name) == 0) return SYS_rt_sigaction;
#endif /* SYS_rt_sigaction */
#ifdef SYS_rt_sigpending
if(strcmp("SYS_rt_sigpending", name) == 0) return SYS_rt_sigpending;
#endif /* SYS_rt_sigpending */
#ifdef SYS_rt_sigprocmask
if(strcmp("SYS_rt_sigprocmask", name) == 0) return SYS_rt_sigprocmask;
#endif /* SYS_rt_sigprocmask */
#ifdef SYS_rt_sigqueueinfo
if(strcmp("SYS_rt_sigqueueinfo", name) == 0) return SYS_rt_sigqueueinfo;
#endif /* SYS_rt_sigqueueinfo */
#ifdef SYS_rt_sigreturn
if(strcmp("SYS_rt_sigreturn", name) == 0) return SYS_rt_sigreturn;
#endif /* SYS_rt_sigreturn */
#ifdef SYS_rt_sigsuspend
if(strcmp("SYS_rt_sigsuspend", name) == 0) return SYS_rt_sigsuspend;
#endif /* SYS_rt_sigsuspend */
#ifdef SYS_rt_sigtimedwait
if(strcmp("SYS_rt_sigtimedwait", name) == 0) return SYS_rt_sigtimedwait;
#endif /* SYS_rt_sigtimedwait */
#ifdef SYS_rt_tgsigqueueinfo
if(strcmp("SYS_rt_tgsigqueueinfo", name) == 0) return SYS_rt_tgsigqueueinfo;
#endif /* SYS_rt_tgsigqueueinfo */
#ifdef SYS_sched_get_priority_max
if(strcmp("SYS_sched_get_priority_max", name) == 0) return SYS_sched_get_priority_max;
#endif /* SYS_sched_get_priority_max */
#ifdef SYS_sched_get_priority_min
if(strcmp("SYS_sched_get_priority_min", name) == 0) return SYS_sched_get_priority_min;
#endif /* SYS_sched_get_priority_min */
#ifdef SYS_sched_getaffinity
if(strcmp("SYS_sched_getaffinity", name) == 0) return SYS_sched_getaffinity;
#endif /* SYS_sched_getaffinity */
#ifdef SYS_sched_getattr
if(strcmp("SYS_sched_getattr", name) == 0) return SYS_sched_getattr;
#endif /* SYS_sched_getattr */
#ifdef SYS_sched_getparam
if(strcmp("SYS_sched_getparam", name) == 0) return SYS_sched_getparam;
#endif /* SYS_sched_getparam */
#ifdef SYS_sched_getscheduler
if(strcmp("SYS_sched_getscheduler", name) == 0) return SYS_sched_getscheduler;
#endif /* SYS_sched_getscheduler */
#ifdef SYS_sched_rr_get_interval
if(strcmp("SYS_sched_rr_get_interval", name) == 0) return SYS_sched_rr_get_interval;
#endif /* SYS_sched_rr_get_interval */
#ifdef SYS_sched_setaffinity
if(strcmp("SYS_sched_setaffinity", name) == 0) return SYS_sched_setaffinity;
#endif /* SYS_sched_setaffinity */
#ifdef SYS_sched_setattr
if(strcmp("SYS_sched_setattr", name) == 0) return SYS_sched_setattr;
#endif /* SYS_sched_setattr */
#ifdef SYS_sched_setparam
if(strcmp("SYS_sched_setparam", name) == 0) return SYS_sched_setparam;
#endif /* SYS_sched_setparam */
#ifdef SYS_sched_setscheduler
if(strcmp("SYS_sched_setscheduler", name) == 0) return SYS_sched_setscheduler;
#endif /* SYS_sched_setscheduler */
#ifdef SYS_sched_yield
if(strcmp("SYS_sched_yield", name) == 0) return SYS_sched_yield;
#endif /* SYS_sched_yield */
#ifdef SYS_seccomp
if(strcmp("SYS_seccomp", name) == 0) return SYS_seccomp;
#endif /* SYS_seccomp */
#ifdef SYS_security
if(strcmp("SYS_security", name) == 0) return SYS_security;
#endif /* SYS_security */
#ifdef SYS_select
if(strcmp("SYS_select", name) == 0) return SYS_select;
#endif /* SYS_select */
#ifdef SYS_semctl
if(strcmp("SYS_semctl", name) == 0) return SYS_semctl;
#endif /* SYS_semctl */
#ifdef SYS_semget
if(strcmp("SYS_semget", name) == 0) return SYS_semget;
#endif /* SYS_semget */
#ifdef SYS_semop
if(strcmp("SYS_semop", name) == 0) return SYS_semop;
#endif /* SYS_semop */
#ifdef SYS_semtimedop
if(strcmp("SYS_semtimedop", name) == 0) return SYS_semtimedop;
#endif /* SYS_semtimedop */
#ifdef SYS_sendfile
if(strcmp("SYS_sendfile", name) == 0) return SYS_sendfile;
#endif /* SYS_sendfile */
#ifdef SYS_sendmmsg
if(strcmp("SYS_sendmmsg", name) == 0) return SYS_sendmmsg;
#endif /* SYS_sendmmsg */
#ifdef SYS_sendmsg
if(strcmp("SYS_sendmsg", name) == 0) return SYS_sendmsg;
#endif /* SYS_sendmsg */
#ifdef SYS_sendto
if(strcmp("SYS_sendto", name) == 0) return SYS_sendto;
#endif /* SYS_sendto */
#ifdef SYS_set_mempolicy
if(strcmp("SYS_set_mempolicy", name) == 0) return SYS_set_mempolicy;
#endif /* SYS_set_mempolicy */
#ifdef SYS_set_robust_list
if(strcmp("SYS_set_robust_list", name) == 0) return SYS_set_robust_list;
#endif /* SYS_set_robust_list */
#ifdef SYS_set_thread_area
if(strcmp("SYS_set_thread_area", name) == 0) return SYS_set_thread_area;
#endif /* SYS_set_thread_area */
#ifdef SYS_set_tid_address
if(strcmp("SYS_set_tid_address", name) == 0) return SYS_set_tid_address;
#endif /* SYS_set_tid_address */
#ifdef SYS_setdomainname
if(strcmp("SYS_setdomainname", name) == 0) return SYS_setdomainname;
#endif /* SYS_setdomainname */
#ifdef SYS_setfsgid
if(strcmp("SYS_setfsgid", name) == 0) return SYS_setfsgid;
#endif /* SYS_setfsgid */
#ifdef SYS_setfsuid
if(strcmp("SYS_setfsuid", name) == 0) return SYS_setfsuid;
#endif /* SYS_setfsuid */
#ifdef SYS_setgid
if(strcmp("SYS_setgid", name) == 0) return SYS_setgid;
#endif /* SYS_setgid */
#ifdef SYS_setgroups
if(strcmp("SYS_setgroups", name) == 0) return SYS_setgroups;
#endif /* SYS_setgroups */
#ifdef SYS_sethostname
if(strcmp("SYS_sethostname", name) == 0) return SYS_sethostname;
#endif /* SYS_sethostname */
#ifdef SYS_setitimer
if(strcmp("SYS_setitimer", name) == 0) return SYS_setitimer;
#endif /* SYS_setitimer */
#ifdef SYS_setns
if(strcmp("SYS_setns", name) == 0) return SYS_setns;
#endif /* SYS_setns */
#ifdef SYS_setpgid
if(strcmp("SYS_setpgid", name) == 0) return SYS_setpgid;
#endif /* SYS_setpgid */
#ifdef SYS_setpriority
if(strcmp("SYS_setpriority", name) == 0) return SYS_setpriority;
#endif /* SYS_setpriority */
#ifdef SYS_setregid
if(strcmp("SYS_setregid", name) == 0) return SYS_setregid;
#endif /* SYS_setregid */
#ifdef SYS_setresgid
if(strcmp("SYS_setresgid", name) == 0) return SYS_setresgid;
#endif /* SYS_setresgid */
#ifdef SYS_setresuid
if(strcmp("SYS_setresuid", name) == 0) return SYS_setresuid;
#endif /* SYS_setresuid */
#ifdef SYS_setreuid
if(strcmp("SYS_setreuid", name) == 0) return SYS_setreuid;
#endif /* SYS_setreuid */
#ifdef SYS_setrlimit
if(strcmp("SYS_setrlimit", name) == 0) return SYS_setrlimit;
#endif /* SYS_setrlimit */
#ifdef SYS_setsid
if(strcmp("SYS_setsid", name) == 0) return SYS_setsid;
#endif /* SYS_setsid */
#ifdef SYS_setsockopt
if(strcmp("SYS_setsockopt", name) == 0) return SYS_setsockopt;
#endif /* SYS_setsockopt */
#ifdef SYS_settimeofday
if(strcmp("SYS_settimeofday", name) == 0) return SYS_settimeofday;
#endif /* SYS_settimeofday */
#ifdef SYS_setuid
if(strcmp("SYS_setuid", name) == 0) return SYS_setuid;
#endif /* SYS_setuid */
#ifdef SYS_setxattr
if(strcmp("SYS_setxattr", name) == 0) return SYS_setxattr;
#endif /* SYS_setxattr */
#ifdef SYS_shmat
if(strcmp("SYS_shmat", name) == 0) return SYS_shmat;
#endif /* SYS_shmat */
#ifdef SYS_shmctl
if(strcmp("SYS_shmctl", name) == 0) return SYS_shmctl;
#endif /* SYS_shmctl */
#ifdef SYS_shmdt
if(strcmp("SYS_shmdt", name) == 0) return SYS_shmdt;
#endif /* SYS_shmdt */
#ifdef SYS_shmget
if(strcmp("SYS_shmget", name) == 0) return SYS_shmget;
#endif /* SYS_shmget */
#ifdef SYS_shutdown
if(strcmp("SYS_shutdown", name) == 0) return SYS_shutdown;
#endif /* SYS_shutdown */
#ifdef SYS_sigaltstack
if(strcmp("SYS_sigaltstack", name) == 0) return SYS_sigaltstack;
#endif /* SYS_sigaltstack */
#ifdef SYS_signalfd
if(strcmp("SYS_signalfd", name) == 0) return SYS_signalfd;
#endif /* SYS_signalfd */
#ifdef SYS_signalfd4
if(strcmp("SYS_signalfd4", name) == 0) return SYS_signalfd4;
#endif /* SYS_signalfd4 */
#ifdef SYS_socket
if(strcmp("SYS_socket", name) == 0) return SYS_socket;
#endif /* SYS_socket */
#ifdef SYS_socketpair
if(strcmp("SYS_socketpair", name) == 0) return SYS_socketpair;
#endif /* SYS_socketpair */
#ifdef SYS_splice
if(strcmp("SYS_splice", name) == 0) return SYS_splice;
#endif /* SYS_splice */
#ifdef SYS_stat
if(strcmp("SYS_stat", name) == 0) return SYS_stat;
#endif /* SYS_stat */
#ifdef SYS_statfs
if(strcmp("SYS_statfs", name) == 0) return SYS_statfs;
#endif /* SYS_statfs */
#ifdef SYS_swapoff
if(strcmp("SYS_swapoff", name) == 0) return SYS_swapoff;
#endif /* SYS_swapoff */
#ifdef SYS_swapon
if(strcmp("SYS_swapon", name) == 0) return SYS_swapon;
#endif /* SYS_swapon */
#ifdef SYS_symlink
if(strcmp("SYS_symlink", name) == 0) return SYS_symlink;
#endif /* SYS_symlink */
#ifdef SYS_symlinkat
if(strcmp("SYS_symlinkat", name) == 0) return SYS_symlinkat;
#endif /* SYS_symlinkat */
#ifdef SYS_sync
if(strcmp("SYS_sync", name) == 0) return SYS_sync;
#endif /* SYS_sync */
#ifdef SYS_sync_file_range
if(strcmp("SYS_sync_file_range", name) == 0) return SYS_sync_file_range;
#endif /* SYS_sync_file_range */
#ifdef SYS_syncfs
if(strcmp("SYS_syncfs", name) == 0) return SYS_syncfs;
#endif /* SYS_syncfs */
#ifdef SYS_sysfs
if(strcmp("SYS_sysfs", name) == 0) return SYS_sysfs;
#endif /* SYS_sysfs */
#ifdef SYS_sysinfo
if(strcmp("SYS_sysinfo", name) == 0) return SYS_sysinfo;
#endif /* SYS_sysinfo */
#ifdef SYS_syslog
if(strcmp("SYS_syslog", name) == 0) return SYS_syslog;
#endif /* SYS_syslog */
#ifdef SYS_tee
if(strcmp("SYS_tee", name) == 0) return SYS_tee;
#endif /* SYS_tee */
#ifdef SYS_tgkill
if(strcmp("SYS_tgkill", name) == 0) return SYS_tgkill;
#endif /* SYS_tgkill */
#ifdef SYS_time
if(strcmp("SYS_time", name) == 0) return SYS_time;
#endif /* SYS_time */
#ifdef SYS_timer_create
if(strcmp("SYS_timer_create", name) == 0) return SYS_timer_create;
#endif /* SYS_timer_create */
#ifdef SYS_timer_delete
if(strcmp("SYS_timer_delete", name) == 0) return SYS_timer_delete;
#endif /* SYS_timer_delete */
#ifdef SYS_timer_getoverrun
if(strcmp("SYS_timer_getoverrun", name) == 0) return SYS_timer_getoverrun;
#endif /* SYS_timer_getoverrun */
#ifdef SYS_timer_gettime
if(strcmp("SYS_timer_gettime", name) == 0) return SYS_timer_gettime;
#endif /* SYS_timer_gettime */
#ifdef SYS_timer_settime
if(strcmp("SYS_timer_settime", name) == 0) return SYS_timer_settime;
#endif /* SYS_timer_settime */
#ifdef SYS_timerfd_create
if(strcmp("SYS_timerfd_create", name) == 0) return SYS_timerfd_create;
#endif /* SYS_timerfd_create */
#ifdef SYS_timerfd_gettime
if(strcmp("SYS_timerfd_gettime", name) == 0) return SYS_timerfd_gettime;
#endif /* SYS_timerfd_gettime */
#ifdef SYS_timerfd_settime
if(strcmp("SYS_timerfd_settime", name) == 0) return SYS_timerfd_settime;
#endif /* SYS_timerfd_settime */
#ifdef SYS_times
if(strcmp("SYS_times", name) == 0) return SYS_times;
#endif /* SYS_times */
#ifdef SYS_tkill
if(strcmp("SYS_tkill", name) == 0) return SYS_tkill;
#endif /* SYS_tkill */
#ifdef SYS_truncate
if(strcmp("SYS_truncate", name) == 0) return SYS_truncate;
#endif /* SYS_truncate */
#ifdef SYS_tuxcall
if(strcmp("SYS_tuxcall", name) == 0) return SYS_tuxcall;
#endif /* SYS_tuxcall */
#ifdef SYS_umask
if(strcmp("SYS_umask", name) == 0) return SYS_umask;
#endif /* SYS_umask */
#ifdef SYS_umount2
if(strcmp("SYS_umount2", name) == 0) return SYS_umount2;
#endif /* SYS_umount2 */
#ifdef SYS_uname
if(strcmp("SYS_uname", name) == 0) return SYS_uname;
#endif /* SYS_uname */
#ifdef SYS_unlink
if(strcmp("SYS_unlink", name) == 0) return SYS_unlink;
#endif /* SYS_unlink */
#ifdef SYS_unlinkat
if(strcmp("SYS_unlinkat", name) == 0) return SYS_unlinkat;
#endif /* SYS_unlinkat */
#ifdef SYS_unshare
if(strcmp("SYS_unshare", name) == 0) return SYS_unshare;
#endif /* SYS_unshare */
#ifdef SYS_uselib
if(strcmp("SYS_uselib", name) == 0) return SYS_uselib;
#endif /* SYS_uselib */
#ifdef SYS_ustat
if(strcmp("SYS_ustat", name) == 0) return SYS_ustat;
#endif /* SYS_ustat */
#ifdef SYS_utime
if(strcmp("SYS_utime", name) == 0) return SYS_utime;
#endif /* SYS_utime */
#ifdef SYS_utimensat
if(strcmp("SYS_utimensat", name) == 0) return SYS_utimensat;
#endif /* SYS_utimensat */
#ifdef SYS_utimes
if(strcmp("SYS_utimes", name) == 0) return SYS_utimes;
#endif /* SYS_utimes */
#ifdef SYS_vfork
if(strcmp("SYS_vfork", name) == 0) return SYS_vfork;
#endif /* SYS_vfork */
#ifdef SYS_vhangup
if(strcmp("SYS_vhangup", name) == 0) return SYS_vhangup;
#endif /* SYS_vhangup */
#ifdef SYS_vmsplice
if(strcmp("SYS_vmsplice", name) == 0) return SYS_vmsplice;
#endif /* SYS_vmsplice */
#ifdef SYS_vserver
if(strcmp("SYS_vserver", name) == 0) return SYS_vserver;
#endif /* SYS_vserver */
#ifdef SYS_wait4
if(strcmp("SYS_wait4", name) == 0) return SYS_wait4;
#endif /* SYS_wait4 */
#ifdef SYS_waitid
if(strcmp("SYS_waitid", name) == 0) return SYS_waitid;
#endif /* SYS_waitid */
#ifdef SYS_write
if(strcmp("SYS_write", name) == 0) return SYS_write;
#endif /* SYS_write */
#ifdef SYS_writev
if(strcmp("SYS_writev", name) == 0) return SYS_writev;
#endif /* SYS_writev */
#ifdef SYS_accept
if(strcmp("SYS_accept", name) == 0) return SYS_accept;
#endif /* SYS_accept */
#ifdef SYS_accept4
if(strcmp("SYS_accept4", name) == 0) return SYS_accept4;
#endif /* SYS_accept4 */
#ifdef SYS_access
if(strcmp("SYS_access", name) == 0) return SYS_access;
#endif /* SYS_access */
#ifdef SYS_acct
if(strcmp("SYS_acct", name) == 0) return SYS_acct;
#endif /* SYS_acct */
#ifdef SYS_add_key
if(strcmp("SYS_add_key", name) == 0) return SYS_add_key;
#endif /* SYS_add_key */
#ifdef SYS_adjtimex
if(strcmp("SYS_adjtimex", name) == 0) return SYS_adjtimex;
#endif /* SYS_adjtimex */
#ifdef SYS_afs_syscall
if(strcmp("SYS_afs_syscall", name) == 0) return SYS_afs_syscall;
#endif /* SYS_afs_syscall */
#ifdef SYS_alarm
if(strcmp("SYS_alarm", name) == 0) return SYS_alarm;
#endif /* SYS_alarm */
#ifdef SYS_arch_prctl
if(strcmp("SYS_arch_prctl", name) == 0) return SYS_arch_prctl;
#endif /* SYS_arch_prctl */
#ifdef SYS_bind
if(strcmp("SYS_bind", name) == 0) return SYS_bind;
#endif /* SYS_bind */
#ifdef SYS_brk
if(strcmp("SYS_brk", name) == 0) return SYS_brk;
#endif /* SYS_brk */
#ifdef SYS_capget
if(strcmp("SYS_capget", name) == 0) return SYS_capget;
#endif /* SYS_capget */
#ifdef SYS_capset
if(strcmp("SYS_capset", name) == 0) return SYS_capset;
#endif /* SYS_capset */
#ifdef SYS_chdir
if(strcmp("SYS_chdir", name) == 0) return SYS_chdir;
#endif /* SYS_chdir */
#ifdef SYS_chmod
if(strcmp("SYS_chmod", name) == 0) return SYS_chmod;
#endif /* SYS_chmod */
#ifdef SYS_chown
if(strcmp("SYS_chown", name) == 0) return SYS_chown;
#endif /* SYS_chown */
#ifdef SYS_chroot
if(strcmp("SYS_chroot", name) == 0) return SYS_chroot;
#endif /* SYS_chroot */
#ifdef SYS_clock_adjtime
if(strcmp("SYS_clock_adjtime", name) == 0) return SYS_clock_adjtime;
#endif /* SYS_clock_adjtime */
#ifdef SYS_clock_getres
if(strcmp("SYS_clock_getres", name) == 0) return SYS_clock_getres;
#endif /* SYS_clock_getres */
#ifdef SYS_clock_gettime
if(strcmp("SYS_clock_gettime", name) == 0) return SYS_clock_gettime;
#endif /* SYS_clock_gettime */
#ifdef SYS_clock_nanosleep
if(strcmp("SYS_clock_nanosleep", name) == 0) return SYS_clock_nanosleep;
#endif /* SYS_clock_nanosleep */
#ifdef SYS_clock_settime
if(strcmp("SYS_clock_settime", name) == 0) return SYS_clock_settime;
#endif /* SYS_clock_settime */
#ifdef SYS_clone
if(strcmp("SYS_clone", name) == 0) return SYS_clone;
#endif /* SYS_clone */
#ifdef SYS_close
if(strcmp("SYS_close", name) == 0) return SYS_close;
#endif /* SYS_close */
#ifdef SYS_connect
if(strcmp("SYS_connect", name) == 0) return SYS_connect;
#endif /* SYS_connect */
#ifdef SYS_creat
if(strcmp("SYS_creat", name) == 0) return SYS_creat;
#endif /* SYS_creat */
#ifdef SYS_delete_module
if(strcmp("SYS_delete_module", name) == 0) return SYS_delete_module;
#endif /* SYS_delete_module */
#ifdef SYS_dup
if(strcmp("SYS_dup", name) == 0) return SYS_dup;
#endif /* SYS_dup */
#ifdef SYS_dup2
if(strcmp("SYS_dup2", name) == 0) return SYS_dup2;
#endif /* SYS_dup2 */
#ifdef SYS_dup3
if(strcmp("SYS_dup3", name) == 0) return SYS_dup3;
#endif /* SYS_dup3 */
#ifdef SYS_epoll_create
if(strcmp("SYS_epoll_create", name) == 0) return SYS_epoll_create;
#endif /* SYS_epoll_create */
#ifdef SYS_epoll_create1
if(strcmp("SYS_epoll_create1", name) == 0) return SYS_epoll_create1;
#endif /* SYS_epoll_create1 */
#ifdef SYS_epoll_ctl
if(strcmp("SYS_epoll_ctl", name) == 0) return SYS_epoll_ctl;
#endif /* SYS_epoll_ctl */
#ifdef SYS_epoll_pwait
if(strcmp("SYS_epoll_pwait", name) == 0) return SYS_epoll_pwait;
#endif /* SYS_epoll_pwait */
#ifdef SYS_epoll_wait
if(strcmp("SYS_epoll_wait", name) == 0) return SYS_epoll_wait;
#endif /* SYS_epoll_wait */
#ifdef SYS_eventfd
if(strcmp("SYS_eventfd", name) == 0) return SYS_eventfd;
#endif /* SYS_eventfd */
#ifdef SYS_eventfd2
if(strcmp("SYS_eventfd2", name) == 0) return SYS_eventfd2;
#endif /* SYS_eventfd2 */
#ifdef SYS_execve
if(strcmp("SYS_execve", name) == 0) return SYS_execve;
#endif /* SYS_execve */
#ifdef SYS_exit
if(strcmp("SYS_exit", name) == 0) return SYS_exit;
#endif /* SYS_exit */
#ifdef SYS_exit_group
if(strcmp("SYS_exit_group", name) == 0) return SYS_exit_group;
#endif /* SYS_exit_group */
#ifdef SYS_faccessat
if(strcmp("SYS_faccessat", name) == 0) return SYS_faccessat;
#endif /* SYS_faccessat */
#ifdef SYS_fadvise64
if(strcmp("SYS_fadvise64", name) == 0) return SYS_fadvise64;
#endif /* SYS_fadvise64 */
#ifdef SYS_fallocate
if(strcmp("SYS_fallocate", name) == 0) return SYS_fallocate;
#endif /* SYS_fallocate */
#ifdef SYS_fanotify_init
if(strcmp("SYS_fanotify_init", name) == 0) return SYS_fanotify_init;
#endif /* SYS_fanotify_init */
#ifdef SYS_fanotify_mark
if(strcmp("SYS_fanotify_mark", name) == 0) return SYS_fanotify_mark;
#endif /* SYS_fanotify_mark */
#ifdef SYS_fchdir
if(strcmp("SYS_fchdir", name) == 0) return SYS_fchdir;
#endif /* SYS_fchdir */
#ifdef SYS_fchmod
if(strcmp("SYS_fchmod", name) == 0) return SYS_fchmod;
#endif /* SYS_fchmod */
#ifdef SYS_fchmodat
if(strcmp("SYS_fchmodat", name) == 0) return SYS_fchmodat;
#endif /* SYS_fchmodat */
#ifdef SYS_fchown
if(strcmp("SYS_fchown", name) == 0) return SYS_fchown;
#endif /* SYS_fchown */
#ifdef SYS_fchownat
if(strcmp("SYS_fchownat", name) == 0) return SYS_fchownat;
#endif /* SYS_fchownat */
#ifdef SYS_fcntl
if(strcmp("SYS_fcntl", name) == 0) return SYS_fcntl;
#endif /* SYS_fcntl */
#ifdef SYS_fdatasync
if(strcmp("SYS_fdatasync", name) == 0) return SYS_fdatasync;
#endif /* SYS_fdatasync */
#ifdef SYS_fgetxattr
if(strcmp("SYS_fgetxattr", name) == 0) return SYS_fgetxattr;
#endif /* SYS_fgetxattr */
#ifdef SYS_finit_module
if(strcmp("SYS_finit_module", name) == 0) return SYS_finit_module;
#endif /* SYS_finit_module */
#ifdef SYS_flistxattr
if(strcmp("SYS_flistxattr", name) == 0) return SYS_flistxattr;
#endif /* SYS_flistxattr */
#ifdef SYS_flock
if(strcmp("SYS_flock", name) == 0) return SYS_flock;
#endif /* SYS_flock */
#ifdef SYS_fork
if(strcmp("SYS_fork", name) == 0) return SYS_fork;
#endif /* SYS_fork */
#ifdef SYS_fremovexattr
if(strcmp("SYS_fremovexattr", name) == 0) return SYS_fremovexattr;
#endif /* SYS_fremovexattr */
#ifdef SYS_fsetxattr
if(strcmp("SYS_fsetxattr", name) == 0) return SYS_fsetxattr;
#endif /* SYS_fsetxattr */
#ifdef SYS_fstat
if(strcmp("SYS_fstat", name) == 0) return SYS_fstat;
#endif /* SYS_fstat */
#ifdef SYS_fstatfs
if(strcmp("SYS_fstatfs", name) == 0) return SYS_fstatfs;
#endif /* SYS_fstatfs */
#ifdef SYS_fsync
if(strcmp("SYS_fsync", name) == 0) return SYS_fsync;
#endif /* SYS_fsync */
#ifdef SYS_ftruncate
if(strcmp("SYS_ftruncate", name) == 0) return SYS_ftruncate;
#endif /* SYS_ftruncate */
#ifdef SYS_futex
if(strcmp("SYS_futex", name) == 0) return SYS_futex;
#endif /* SYS_futex */
#ifdef SYS_futimesat
if(strcmp("SYS_futimesat", name) == 0) return SYS_futimesat;
#endif /* SYS_futimesat */
#ifdef SYS_get_mempolicy
if(strcmp("SYS_get_mempolicy", name) == 0) return SYS_get_mempolicy;
#endif /* SYS_get_mempolicy */
#ifdef SYS_get_robust_list
if(strcmp("SYS_get_robust_list", name) == 0) return SYS_get_robust_list;
#endif /* SYS_get_robust_list */
#ifdef SYS_getcpu
if(strcmp("SYS_getcpu", name) == 0) return SYS_getcpu;
#endif /* SYS_getcpu */
#ifdef SYS_getcwd
if(strcmp("SYS_getcwd", name) == 0) return SYS_getcwd;
#endif /* SYS_getcwd */
#ifdef SYS_getdents
if(strcmp("SYS_getdents", name) == 0) return SYS_getdents;
#endif /* SYS_getdents */
#ifdef SYS_getdents64
if(strcmp("SYS_getdents64", name) == 0) return SYS_getdents64;
#endif /* SYS_getdents64 */
#ifdef SYS_getegid
if(strcmp("SYS_getegid", name) == 0) return SYS_getegid;
#endif /* SYS_getegid */
#ifdef SYS_geteuid
if(strcmp("SYS_geteuid", name) == 0) return SYS_geteuid;
#endif /* SYS_geteuid */
#ifdef SYS_getgid
if(strcmp("SYS_getgid", name) == 0) return SYS_getgid;
#endif /* SYS_getgid */
#ifdef SYS_getgroups
if(strcmp("SYS_getgroups", name) == 0) return SYS_getgroups;
#endif /* SYS_getgroups */
#ifdef SYS_getitimer
if(strcmp("SYS_getitimer", name) == 0) return SYS_getitimer;
#endif /* SYS_getitimer */
#ifdef SYS_getpeername
if(strcmp("SYS_getpeername", name) == 0) return SYS_getpeername;
#endif /* SYS_getpeername */
#ifdef SYS_getpgid
if(strcmp("SYS_getpgid", name) == 0) return SYS_getpgid;
#endif /* SYS_getpgid */
#ifdef SYS_getpgrp
if(strcmp("SYS_getpgrp", name) == 0) return SYS_getpgrp;
#endif /* SYS_getpgrp */
#ifdef SYS_getpid
if(strcmp("SYS_getpid", name) == 0) return SYS_getpid;
#endif /* SYS_getpid */
#ifdef SYS_getpmsg
if(strcmp("SYS_getpmsg", name) == 0) return SYS_getpmsg;
#endif /* SYS_getpmsg */
#ifdef SYS_getppid
if(strcmp("SYS_getppid", name) == 0) return SYS_getppid;
#endif /* SYS_getppid */
#ifdef SYS_getpriority
if(strcmp("SYS_getpriority", name) == 0) return SYS_getpriority;
#endif /* SYS_getpriority */
#ifdef SYS_getresgid
if(strcmp("SYS_getresgid", name) == 0) return SYS_getresgid;
#endif /* SYS_getresgid */
#ifdef SYS_getresuid
if(strcmp("SYS_getresuid", name) == 0) return SYS_getresuid;
#endif /* SYS_getresuid */
#ifdef SYS_getrlimit
if(strcmp("SYS_getrlimit", name) == 0) return SYS_getrlimit;
#endif /* SYS_getrlimit */
#ifdef SYS_getrusage
if(strcmp("SYS_getrusage", name) == 0) return SYS_getrusage;
#endif /* SYS_getrusage */
#ifdef SYS_getsid
if(strcmp("SYS_getsid", name) == 0) return SYS_getsid;
#endif /* SYS_getsid */
#ifdef SYS_getsockname
if(strcmp("SYS_getsockname", name) == 0) return SYS_getsockname;
#endif /* SYS_getsockname */
#ifdef SYS_getsockopt
if(strcmp("SYS_getsockopt", name) == 0) return SYS_getsockopt;
#endif /* SYS_getsockopt */
#ifdef SYS_gettid
if(strcmp("SYS_gettid", name) == 0) return SYS_gettid;
#endif /* SYS_gettid */
#ifdef SYS_gettimeofday
if(strcmp("SYS_gettimeofday", name) == 0) return SYS_gettimeofday;
#endif /* SYS_gettimeofday */
#ifdef SYS_getuid
if(strcmp("SYS_getuid", name) == 0) return SYS_getuid;
#endif /* SYS_getuid */
#ifdef SYS_getxattr
if(strcmp("SYS_getxattr", name) == 0) return SYS_getxattr;
#endif /* SYS_getxattr */
#ifdef SYS_init_module
if(strcmp("SYS_init_module", name) == 0) return SYS_init_module;
#endif /* SYS_init_module */
#ifdef SYS_inotify_add_watch
if(strcmp("SYS_inotify_add_watch", name) == 0) return SYS_inotify_add_watch;
#endif /* SYS_inotify_add_watch */
#ifdef SYS_inotify_init
if(strcmp("SYS_inotify_init", name) == 0) return SYS_inotify_init;
#endif /* SYS_inotify_init */
#ifdef SYS_inotify_init1
if(strcmp("SYS_inotify_init1", name) == 0) return SYS_inotify_init1;
#endif /* SYS_inotify_init1 */
#ifdef SYS_inotify_rm_watch
if(strcmp("SYS_inotify_rm_watch", name) == 0) return SYS_inotify_rm_watch;
#endif /* SYS_inotify_rm_watch */
#ifdef SYS_io_cancel
if(strcmp("SYS_io_cancel", name) == 0) return SYS_io_cancel;
#endif /* SYS_io_cancel */
#ifdef SYS_io_destroy
if(strcmp("SYS_io_destroy", name) == 0) return SYS_io_destroy;
#endif /* SYS_io_destroy */
#ifdef SYS_io_getevents
if(strcmp("SYS_io_getevents", name) == 0) return SYS_io_getevents;
#endif /* SYS_io_getevents */
#ifdef SYS_io_setup
if(strcmp("SYS_io_setup", name) == 0) return SYS_io_setup;
#endif /* SYS_io_setup */
#ifdef SYS_io_submit
if(strcmp("SYS_io_submit", name) == 0) return SYS_io_submit;
#endif /* SYS_io_submit */
#ifdef SYS_ioctl
if(strcmp("SYS_ioctl", name) == 0) return SYS_ioctl;
#endif /* SYS_ioctl */
#ifdef SYS_ioperm
if(strcmp("SYS_ioperm", name) == 0) return SYS_ioperm;
#endif /* SYS_ioperm */
#ifdef SYS_iopl
if(strcmp("SYS_iopl", name) == 0) return SYS_iopl;
#endif /* SYS_iopl */
#ifdef SYS_ioprio_get
if(strcmp("SYS_ioprio_get", name) == 0) return SYS_ioprio_get;
#endif /* SYS_ioprio_get */
#ifdef SYS_ioprio_set
if(strcmp("SYS_ioprio_set", name) == 0) return SYS_ioprio_set;
#endif /* SYS_ioprio_set */
#ifdef SYS_kcmp
if(strcmp("SYS_kcmp", name) == 0) return SYS_kcmp;
#endif /* SYS_kcmp */
#ifdef SYS_kexec_load
if(strcmp("SYS_kexec_load", name) == 0) return SYS_kexec_load;
#endif /* SYS_kexec_load */
#ifdef SYS_keyctl
if(strcmp("SYS_keyctl", name) == 0) return SYS_keyctl;
#endif /* SYS_keyctl */
#ifdef SYS_kill
if(strcmp("SYS_kill", name) == 0) return SYS_kill;
#endif /* SYS_kill */
#ifdef SYS_lchown
if(strcmp("SYS_lchown", name) == 0) return SYS_lchown;
#endif /* SYS_lchown */
#ifdef SYS_lgetxattr
if(strcmp("SYS_lgetxattr", name) == 0) return SYS_lgetxattr;
#endif /* SYS_lgetxattr */
#ifdef SYS_link
if(strcmp("SYS_link", name) == 0) return SYS_link;
#endif /* SYS_link */
#ifdef SYS_linkat
if(strcmp("SYS_linkat", name) == 0) return SYS_linkat;
#endif /* SYS_linkat */
#ifdef SYS_listen
if(strcmp("SYS_listen", name) == 0) return SYS_listen;
#endif /* SYS_listen */
#ifdef SYS_listxattr
if(strcmp("SYS_listxattr", name) == 0) return SYS_listxattr;
#endif /* SYS_listxattr */
#ifdef SYS_llistxattr
if(strcmp("SYS_llistxattr", name) == 0) return SYS_llistxattr;
#endif /* SYS_llistxattr */
#ifdef SYS_lookup_dcookie
if(strcmp("SYS_lookup_dcookie", name) == 0) return SYS_lookup_dcookie;
#endif /* SYS_lookup_dcookie */
#ifdef SYS_lremovexattr
if(strcmp("SYS_lremovexattr", name) == 0) return SYS_lremovexattr;
#endif /* SYS_lremovexattr */
#ifdef SYS_lseek
if(strcmp("SYS_lseek", name) == 0) return SYS_lseek;
#endif /* SYS_lseek */
#ifdef SYS_lsetxattr
if(strcmp("SYS_lsetxattr", name) == 0) return SYS_lsetxattr;
#endif /* SYS_lsetxattr */
#ifdef SYS_lstat
if(strcmp("SYS_lstat", name) == 0) return SYS_lstat;
#endif /* SYS_lstat */
#ifdef SYS_madvise
if(strcmp("SYS_madvise", name) == 0) return SYS_madvise;
#endif /* SYS_madvise */
#ifdef SYS_mbind
if(strcmp("SYS_mbind", name) == 0) return SYS_mbind;
#endif /* SYS_mbind */
#ifdef SYS_migrate_pages
if(strcmp("SYS_migrate_pages", name) == 0) return SYS_migrate_pages;
#endif /* SYS_migrate_pages */
#ifdef SYS_mincore
if(strcmp("SYS_mincore", name) == 0) return SYS_mincore;
#endif /* SYS_mincore */
#ifdef SYS_mkdir
if(strcmp("SYS_mkdir", name) == 0) return SYS_mkdir;
#endif /* SYS_mkdir */
#ifdef SYS_mkdirat
if(strcmp("SYS_mkdirat", name) == 0) return SYS_mkdirat;
#endif /* SYS_mkdirat */
#ifdef SYS_mknod
if(strcmp("SYS_mknod", name) == 0) return SYS_mknod;
#endif /* SYS_mknod */
#ifdef SYS_mknodat
if(strcmp("SYS_mknodat", name) == 0) return SYS_mknodat;
#endif /* SYS_mknodat */
#ifdef SYS_mlock
if(strcmp("SYS_mlock", name) == 0) return SYS_mlock;
#endif /* SYS_mlock */
#ifdef SYS_mlockall
if(strcmp("SYS_mlockall", name) == 0) return SYS_mlockall;
#endif /* SYS_mlockall */
#ifdef SYS_mmap
if(strcmp("SYS_mmap", name) == 0) return SYS_mmap;
#endif /* SYS_mmap */
#ifdef SYS_modify_ldt
if(strcmp("SYS_modify_ldt", name) == 0) return SYS_modify_ldt;
#endif /* SYS_modify_ldt */
#ifdef SYS_mount
if(strcmp("SYS_mount", name) == 0) return SYS_mount;
#endif /* SYS_mount */
#ifdef SYS_move_pages
if(strcmp("SYS_move_pages", name) == 0) return SYS_move_pages;
#endif /* SYS_move_pages */
#ifdef SYS_mprotect
if(strcmp("SYS_mprotect", name) == 0) return SYS_mprotect;
#endif /* SYS_mprotect */
#ifdef SYS_mq_getsetattr
if(strcmp("SYS_mq_getsetattr", name) == 0) return SYS_mq_getsetattr;
#endif /* SYS_mq_getsetattr */
#ifdef SYS_mq_notify
if(strcmp("SYS_mq_notify", name) == 0) return SYS_mq_notify;
#endif /* SYS_mq_notify */
#ifdef SYS_mq_open
if(strcmp("SYS_mq_open", name) == 0) return SYS_mq_open;
#endif /* SYS_mq_open */
#ifdef SYS_mq_timedreceive
if(strcmp("SYS_mq_timedreceive", name) == 0) return SYS_mq_timedreceive;
#endif /* SYS_mq_timedreceive */
#ifdef SYS_mq_timedsend
if(strcmp("SYS_mq_timedsend", name) == 0) return SYS_mq_timedsend;
#endif /* SYS_mq_timedsend */
#ifdef SYS_mq_unlink
if(strcmp("SYS_mq_unlink", name) == 0) return SYS_mq_unlink;
#endif /* SYS_mq_unlink */
#ifdef SYS_mremap
if(strcmp("SYS_mremap", name) == 0) return SYS_mremap;
#endif /* SYS_mremap */
#ifdef SYS_msgctl
if(strcmp("SYS_msgctl", name) == 0) return SYS_msgctl;
#endif /* SYS_msgctl */
#ifdef SYS_msgget
if(strcmp("SYS_msgget", name) == 0) return SYS_msgget;
#endif /* SYS_msgget */
#ifdef SYS_msgrcv
if(strcmp("SYS_msgrcv", name) == 0) return SYS_msgrcv;
#endif /* SYS_msgrcv */
#ifdef SYS_msgsnd
if(strcmp("SYS_msgsnd", name) == 0) return SYS_msgsnd;
#endif /* SYS_msgsnd */
#ifdef SYS_msync
if(strcmp("SYS_msync", name) == 0) return SYS_msync;
#endif /* SYS_msync */
#ifdef SYS_munlock
if(strcmp("SYS_munlock", name) == 0) return SYS_munlock;
#endif /* SYS_munlock */
#ifdef SYS_munlockall
if(strcmp("SYS_munlockall", name) == 0) return SYS_munlockall;
#endif /* SYS_munlockall */
#ifdef SYS_munmap
if(strcmp("SYS_munmap", name) == 0) return SYS_munmap;
#endif /* SYS_munmap */
#ifdef SYS_name_to_handle_at
if(strcmp("SYS_name_to_handle_at", name) == 0) return SYS_name_to_handle_at;
#endif /* SYS_name_to_handle_at */
#ifdef SYS_nanosleep
if(strcmp("SYS_nanosleep", name) == 0) return SYS_nanosleep;
#endif /* SYS_nanosleep */
#ifdef SYS_newfstatat
if(strcmp("SYS_newfstatat", name) == 0) return SYS_newfstatat;
#endif /* SYS_newfstatat */
#ifdef SYS_open
if(strcmp("SYS_open", name) == 0) return SYS_open;
#endif /* SYS_open */
#ifdef SYS_open_by_handle_at
if(strcmp("SYS_open_by_handle_at", name) == 0) return SYS_open_by_handle_at;
#endif /* SYS_open_by_handle_at */
#ifdef SYS_openat
if(strcmp("SYS_openat", name) == 0) return SYS_openat;
#endif /* SYS_openat */
#ifdef SYS_pause
if(strcmp("SYS_pause", name) == 0) return SYS_pause;
#endif /* SYS_pause */
#ifdef SYS_perf_event_open
if(strcmp("SYS_perf_event_open", name) == 0) return SYS_perf_event_open;
#endif /* SYS_perf_event_open */
#ifdef SYS_personality
if(strcmp("SYS_personality", name) == 0) return SYS_personality;
#endif /* SYS_personality */
#ifdef SYS_pipe
if(strcmp("SYS_pipe", name) == 0) return SYS_pipe;
#endif /* SYS_pipe */
#ifdef SYS_pipe2
if(strcmp("SYS_pipe2", name) == 0) return SYS_pipe2;
#endif /* SYS_pipe2 */
#ifdef SYS_pivot_root
if(strcmp("SYS_pivot_root", name) == 0) return SYS_pivot_root;
#endif /* SYS_pivot_root */
#ifdef SYS_poll
if(strcmp("SYS_poll", name) == 0) return SYS_poll;
#endif /* SYS_poll */
#ifdef SYS_ppoll
if(strcmp("SYS_ppoll", name) == 0) return SYS_ppoll;
#endif /* SYS_ppoll */
#ifdef SYS_prctl
if(strcmp("SYS_prctl", name) == 0) return SYS_prctl;
#endif /* SYS_prctl */
#ifdef SYS_pread64
if(strcmp("SYS_pread64", name) == 0) return SYS_pread64;
#endif /* SYS_pread64 */
#ifdef SYS_preadv
if(strcmp("SYS_preadv", name) == 0) return SYS_preadv;
#endif /* SYS_preadv */
#ifdef SYS_prlimit64
if(strcmp("SYS_prlimit64", name) == 0) return SYS_prlimit64;
#endif /* SYS_prlimit64 */
#ifdef SYS_process_vm_readv
if(strcmp("SYS_process_vm_readv", name) == 0) return SYS_process_vm_readv;
#endif /* SYS_process_vm_readv */
#ifdef SYS_process_vm_writev
if(strcmp("SYS_process_vm_writev", name) == 0) return SYS_process_vm_writev;
#endif /* SYS_process_vm_writev */
#ifdef SYS_pselect6
if(strcmp("SYS_pselect6", name) == 0) return SYS_pselect6;
#endif /* SYS_pselect6 */
#ifdef SYS_ptrace
if(strcmp("SYS_ptrace", name) == 0) return SYS_ptrace;
#endif /* SYS_ptrace */
#ifdef SYS_putpmsg
if(strcmp("SYS_putpmsg", name) == 0) return SYS_putpmsg;
#endif /* SYS_putpmsg */
#ifdef SYS_pwrite64
if(strcmp("SYS_pwrite64", name) == 0) return SYS_pwrite64;
#endif /* SYS_pwrite64 */
#ifdef SYS_pwritev
if(strcmp("SYS_pwritev", name) == 0) return SYS_pwritev;
#endif /* SYS_pwritev */
#ifdef SYS_quotactl
if(strcmp("SYS_quotactl", name) == 0) return SYS_quotactl;
#endif /* SYS_quotactl */
#ifdef SYS_read
if(strcmp("SYS_read", name) == 0) return SYS_read;
#endif /* SYS_read */
#ifdef SYS_readahead
if(strcmp("SYS_readahead", name) == 0) return SYS_readahead;
#endif /* SYS_readahead */
#ifdef SYS_readlink
if(strcmp("SYS_readlink", name) == 0) return SYS_readlink;
#endif /* SYS_readlink */
#ifdef SYS_readlinkat
if(strcmp("SYS_readlinkat", name) == 0) return SYS_readlinkat;
#endif /* SYS_readlinkat */
#ifdef SYS_readv
if(strcmp("SYS_readv", name) == 0) return SYS_readv;
#endif /* SYS_readv */
#ifdef SYS_reboot
if(strcmp("SYS_reboot", name) == 0) return SYS_reboot;
#endif /* SYS_reboot */
#ifdef SYS_recvfrom
if(strcmp("SYS_recvfrom", name) == 0) return SYS_recvfrom;
#endif /* SYS_recvfrom */
#ifdef SYS_recvmmsg
if(strcmp("SYS_recvmmsg", name) == 0) return SYS_recvmmsg;
#endif /* SYS_recvmmsg */
#ifdef SYS_recvmsg
if(strcmp("SYS_recvmsg", name) == 0) return SYS_recvmsg;
#endif /* SYS_recvmsg */
#ifdef SYS_remap_file_pages
if(strcmp("SYS_remap_file_pages", name) == 0) return SYS_remap_file_pages;
#endif /* SYS_remap_file_pages */
#ifdef SYS_removexattr
if(strcmp("SYS_removexattr", name) == 0) return SYS_removexattr;
#endif /* SYS_removexattr */
#ifdef SYS_rename
if(strcmp("SYS_rename", name) == 0) return SYS_rename;
#endif /* SYS_rename */
#ifdef SYS_renameat
if(strcmp("SYS_renameat", name) == 0) return SYS_renameat;
#endif /* SYS_renameat */
#ifdef SYS_renameat2
if(strcmp("SYS_renameat2", name) == 0) return SYS_renameat2;
#endif /* SYS_renameat2 */
#ifdef SYS_request_key
if(strcmp("SYS_request_key", name) == 0) return SYS_request_key;
#endif /* SYS_request_key */
#ifdef SYS_restart_syscall
if(strcmp("SYS_restart_syscall", name) == 0) return SYS_restart_syscall;
#endif /* SYS_restart_syscall */
#ifdef SYS_rmdir
if(strcmp("SYS_rmdir", name) == 0) return SYS_rmdir;
#endif /* SYS_rmdir */
#ifdef SYS_rt_sigaction
if(strcmp("SYS_rt_sigaction", name) == 0) return SYS_rt_sigaction;
#endif /* SYS_rt_sigaction */
#ifdef SYS_rt_sigpending
if(strcmp("SYS_rt_sigpending", name) == 0) return SYS_rt_sigpending;
#endif /* SYS_rt_sigpending */
#ifdef SYS_rt_sigprocmask
if(strcmp("SYS_rt_sigprocmask", name) == 0) return SYS_rt_sigprocmask;
#endif /* SYS_rt_sigprocmask */
#ifdef SYS_rt_sigqueueinfo
if(strcmp("SYS_rt_sigqueueinfo", name) == 0) return SYS_rt_sigqueueinfo;
#endif /* SYS_rt_sigqueueinfo */
#ifdef SYS_rt_sigreturn
if(strcmp("SYS_rt_sigreturn", name) == 0) return SYS_rt_sigreturn;
#endif /* SYS_rt_sigreturn */
#ifdef SYS_rt_sigsuspend
if(strcmp("SYS_rt_sigsuspend", name) == 0) return SYS_rt_sigsuspend;
#endif /* SYS_rt_sigsuspend */
#ifdef SYS_rt_sigtimedwait
if(strcmp("SYS_rt_sigtimedwait", name) == 0) return SYS_rt_sigtimedwait;
#endif /* SYS_rt_sigtimedwait */
#ifdef SYS_rt_tgsigqueueinfo
if(strcmp("SYS_rt_tgsigqueueinfo", name) == 0) return SYS_rt_tgsigqueueinfo;
#endif /* SYS_rt_tgsigqueueinfo */
#ifdef SYS_sched_get_priority_max
if(strcmp("SYS_sched_get_priority_max", name) == 0) return SYS_sched_get_priority_max;
#endif /* SYS_sched_get_priority_max */
#ifdef SYS_sched_get_priority_min
if(strcmp("SYS_sched_get_priority_min", name) == 0) return SYS_sched_get_priority_min;
#endif /* SYS_sched_get_priority_min */
#ifdef SYS_sched_getaffinity
if(strcmp("SYS_sched_getaffinity", name) == 0) return SYS_sched_getaffinity;
#endif /* SYS_sched_getaffinity */
#ifdef SYS_sched_getattr
if(strcmp("SYS_sched_getattr", name) == 0) return SYS_sched_getattr;
#endif /* SYS_sched_getattr */
#ifdef SYS_sched_getparam
if(strcmp("SYS_sched_getparam", name) == 0) return SYS_sched_getparam;
#endif /* SYS_sched_getparam */
#ifdef SYS_sched_getscheduler
if(strcmp("SYS_sched_getscheduler", name) == 0) return SYS_sched_getscheduler;
#endif /* SYS_sched_getscheduler */
#ifdef SYS_sched_rr_get_interval
if(strcmp("SYS_sched_rr_get_interval", name) == 0) return SYS_sched_rr_get_interval;
#endif /* SYS_sched_rr_get_interval */
#ifdef SYS_sched_setaffinity
if(strcmp("SYS_sched_setaffinity", name) == 0) return SYS_sched_setaffinity;
#endif /* SYS_sched_setaffinity */
#ifdef SYS_sched_setattr
if(strcmp("SYS_sched_setattr", name) == 0) return SYS_sched_setattr;
#endif /* SYS_sched_setattr */
#ifdef SYS_sched_setparam
if(strcmp("SYS_sched_setparam", name) == 0) return SYS_sched_setparam;
#endif /* SYS_sched_setparam */
#ifdef SYS_sched_setscheduler
if(strcmp("SYS_sched_setscheduler", name) == 0) return SYS_sched_setscheduler;
#endif /* SYS_sched_setscheduler */
#ifdef SYS_sched_yield
if(strcmp("SYS_sched_yield", name) == 0) return SYS_sched_yield;
#endif /* SYS_sched_yield */
#ifdef SYS_seccomp
if(strcmp("SYS_seccomp", name) == 0) return SYS_seccomp;
#endif /* SYS_seccomp */
#ifdef SYS_security
if(strcmp("SYS_security", name) == 0) return SYS_security;
#endif /* SYS_security */
#ifdef SYS_select
if(strcmp("SYS_select", name) == 0) return SYS_select;
#endif /* SYS_select */
#ifdef SYS_semctl
if(strcmp("SYS_semctl", name) == 0) return SYS_semctl;
#endif /* SYS_semctl */
#ifdef SYS_semget
if(strcmp("SYS_semget", name) == 0) return SYS_semget;
#endif /* SYS_semget */
#ifdef SYS_semop
if(strcmp("SYS_semop", name) == 0) return SYS_semop;
#endif /* SYS_semop */
#ifdef SYS_semtimedop
if(strcmp("SYS_semtimedop", name) == 0) return SYS_semtimedop;
#endif /* SYS_semtimedop */
#ifdef SYS_sendfile
if(strcmp("SYS_sendfile", name) == 0) return SYS_sendfile;
#endif /* SYS_sendfile */
#ifdef SYS_sendmmsg
if(strcmp("SYS_sendmmsg", name) == 0) return SYS_sendmmsg;
#endif /* SYS_sendmmsg */
#ifdef SYS_sendmsg
if(strcmp("SYS_sendmsg", name) == 0) return SYS_sendmsg;
#endif /* SYS_sendmsg */
#ifdef SYS_sendto
if(strcmp("SYS_sendto", name) == 0) return SYS_sendto;
#endif /* SYS_sendto */
#ifdef SYS_set_mempolicy
if(strcmp("SYS_set_mempolicy", name) == 0) return SYS_set_mempolicy;
#endif /* SYS_set_mempolicy */
#ifdef SYS_set_robust_list
if(strcmp("SYS_set_robust_list", name) == 0) return SYS_set_robust_list;
#endif /* SYS_set_robust_list */
#ifdef SYS_set_tid_address
if(strcmp("SYS_set_tid_address", name) == 0) return SYS_set_tid_address;
#endif /* SYS_set_tid_address */
#ifdef SYS_setdomainname
if(strcmp("SYS_setdomainname", name) == 0) return SYS_setdomainname;
#endif /* SYS_setdomainname */
#ifdef SYS_setfsgid
if(strcmp("SYS_setfsgid", name) == 0) return SYS_setfsgid;
#endif /* SYS_setfsgid */
#ifdef SYS_setfsuid
if(strcmp("SYS_setfsuid", name) == 0) return SYS_setfsuid;
#endif /* SYS_setfsuid */
#ifdef SYS_setgid
if(strcmp("SYS_setgid", name) == 0) return SYS_setgid;
#endif /* SYS_setgid */
#ifdef SYS_setgroups
if(strcmp("SYS_setgroups", name) == 0) return SYS_setgroups;
#endif /* SYS_setgroups */
#ifdef SYS_sethostname
if(strcmp("SYS_sethostname", name) == 0) return SYS_sethostname;
#endif /* SYS_sethostname */
#ifdef SYS_setitimer
if(strcmp("SYS_setitimer", name) == 0) return SYS_setitimer;
#endif /* SYS_setitimer */
#ifdef SYS_setns
if(strcmp("SYS_setns", name) == 0) return SYS_setns;
#endif /* SYS_setns */
#ifdef SYS_setpgid
if(strcmp("SYS_setpgid", name) == 0) return SYS_setpgid;
#endif /* SYS_setpgid */
#ifdef SYS_setpriority
if(strcmp("SYS_setpriority", name) == 0) return SYS_setpriority;
#endif /* SYS_setpriority */
#ifdef SYS_setregid
if(strcmp("SYS_setregid", name) == 0) return SYS_setregid;
#endif /* SYS_setregid */
#ifdef SYS_setresgid
if(strcmp("SYS_setresgid", name) == 0) return SYS_setresgid;
#endif /* SYS_setresgid */
#ifdef SYS_setresuid
if(strcmp("SYS_setresuid", name) == 0) return SYS_setresuid;
#endif /* SYS_setresuid */
#ifdef SYS_setreuid
if(strcmp("SYS_setreuid", name) == 0) return SYS_setreuid;
#endif /* SYS_setreuid */
#ifdef SYS_setrlimit
if(strcmp("SYS_setrlimit", name) == 0) return SYS_setrlimit;
#endif /* SYS_setrlimit */
#ifdef SYS_setsid
if(strcmp("SYS_setsid", name) == 0) return SYS_setsid;
#endif /* SYS_setsid */
#ifdef SYS_setsockopt
if(strcmp("SYS_setsockopt", name) == 0) return SYS_setsockopt;
#endif /* SYS_setsockopt */
#ifdef SYS_settimeofday
if(strcmp("SYS_settimeofday", name) == 0) return SYS_settimeofday;
#endif /* SYS_settimeofday */
#ifdef SYS_setuid
if(strcmp("SYS_setuid", name) == 0) return SYS_setuid;
#endif /* SYS_setuid */
#ifdef SYS_setxattr
if(strcmp("SYS_setxattr", name) == 0) return SYS_setxattr;
#endif /* SYS_setxattr */
#ifdef SYS_shmat
if(strcmp("SYS_shmat", name) == 0) return SYS_shmat;
#endif /* SYS_shmat */
#ifdef SYS_shmctl
if(strcmp("SYS_shmctl", name) == 0) return SYS_shmctl;
#endif /* SYS_shmctl */
#ifdef SYS_shmdt
if(strcmp("SYS_shmdt", name) == 0) return SYS_shmdt;
#endif /* SYS_shmdt */
#ifdef SYS_shmget
if(strcmp("SYS_shmget", name) == 0) return SYS_shmget;
#endif /* SYS_shmget */
#ifdef SYS_shutdown
if(strcmp("SYS_shutdown", name) == 0) return SYS_shutdown;
#endif /* SYS_shutdown */
#ifdef SYS_sigaltstack
if(strcmp("SYS_sigaltstack", name) == 0) return SYS_sigaltstack;
#endif /* SYS_sigaltstack */
#ifdef SYS_signalfd
if(strcmp("SYS_signalfd", name) == 0) return SYS_signalfd;
#endif /* SYS_signalfd */
#ifdef SYS_signalfd4
if(strcmp("SYS_signalfd4", name) == 0) return SYS_signalfd4;
#endif /* SYS_signalfd4 */
#ifdef SYS_socket
if(strcmp("SYS_socket", name) == 0) return SYS_socket;
#endif /* SYS_socket */
#ifdef SYS_socketpair
if(strcmp("SYS_socketpair", name) == 0) return SYS_socketpair;
#endif /* SYS_socketpair */
#ifdef SYS_splice
if(strcmp("SYS_splice", name) == 0) return SYS_splice;
#endif /* SYS_splice */
#ifdef SYS_stat
if(strcmp("SYS_stat", name) == 0) return SYS_stat;
#endif /* SYS_stat */
#ifdef SYS_statfs
if(strcmp("SYS_statfs", name) == 0) return SYS_statfs;
#endif /* SYS_statfs */
#ifdef SYS_swapoff
if(strcmp("SYS_swapoff", name) == 0) return SYS_swapoff;
#endif /* SYS_swapoff */
#ifdef SYS_swapon
if(strcmp("SYS_swapon", name) == 0) return SYS_swapon;
#endif /* SYS_swapon */
#ifdef SYS_symlink
if(strcmp("SYS_symlink", name) == 0) return SYS_symlink;
#endif /* SYS_symlink */
#ifdef SYS_symlinkat
if(strcmp("SYS_symlinkat", name) == 0) return SYS_symlinkat;
#endif /* SYS_symlinkat */
#ifdef SYS_sync
if(strcmp("SYS_sync", name) == 0) return SYS_sync;
#endif /* SYS_sync */
#ifdef SYS_sync_file_range
if(strcmp("SYS_sync_file_range", name) == 0) return SYS_sync_file_range;
#endif /* SYS_sync_file_range */
#ifdef SYS_syncfs
if(strcmp("SYS_syncfs", name) == 0) return SYS_syncfs;
#endif /* SYS_syncfs */
#ifdef SYS_sysfs
if(strcmp("SYS_sysfs", name) == 0) return SYS_sysfs;
#endif /* SYS_sysfs */
#ifdef SYS_sysinfo
if(strcmp("SYS_sysinfo", name) == 0) return SYS_sysinfo;
#endif /* SYS_sysinfo */
#ifdef SYS_syslog
if(strcmp("SYS_syslog", name) == 0) return SYS_syslog;
#endif /* SYS_syslog */
#ifdef SYS_tee
if(strcmp("SYS_tee", name) == 0) return SYS_tee;
#endif /* SYS_tee */
#ifdef SYS_tgkill
if(strcmp("SYS_tgkill", name) == 0) return SYS_tgkill;
#endif /* SYS_tgkill */
#ifdef SYS_time
if(strcmp("SYS_time", name) == 0) return SYS_time;
#endif /* SYS_time */
#ifdef SYS_timer_create
if(strcmp("SYS_timer_create", name) == 0) return SYS_timer_create;
#endif /* SYS_timer_create */
#ifdef SYS_timer_delete
if(strcmp("SYS_timer_delete", name) == 0) return SYS_timer_delete;
#endif /* SYS_timer_delete */
#ifdef SYS_timer_getoverrun
if(strcmp("SYS_timer_getoverrun", name) == 0) return SYS_timer_getoverrun;
#endif /* SYS_timer_getoverrun */
#ifdef SYS_timer_gettime
if(strcmp("SYS_timer_gettime", name) == 0) return SYS_timer_gettime;
#endif /* SYS_timer_gettime */
#ifdef SYS_timer_settime
if(strcmp("SYS_timer_settime", name) == 0) return SYS_timer_settime;
#endif /* SYS_timer_settime */
#ifdef SYS_timerfd_create
if(strcmp("SYS_timerfd_create", name) == 0) return SYS_timerfd_create;
#endif /* SYS_timerfd_create */
#ifdef SYS_timerfd_gettime
if(strcmp("SYS_timerfd_gettime", name) == 0) return SYS_timerfd_gettime;
#endif /* SYS_timerfd_gettime */
#ifdef SYS_timerfd_settime
if(strcmp("SYS_timerfd_settime", name) == 0) return SYS_timerfd_settime;
#endif /* SYS_timerfd_settime */
#ifdef SYS_times
if(strcmp("SYS_times", name) == 0) return SYS_times;
#endif /* SYS_times */
#ifdef SYS_tkill
if(strcmp("SYS_tkill", name) == 0) return SYS_tkill;
#endif /* SYS_tkill */
#ifdef SYS_truncate
if(strcmp("SYS_truncate", name) == 0) return SYS_truncate;
#endif /* SYS_truncate */
#ifdef SYS_tuxcall
if(strcmp("SYS_tuxcall", name) == 0) return SYS_tuxcall;
#endif /* SYS_tuxcall */
#ifdef SYS_umask
if(strcmp("SYS_umask", name) == 0) return SYS_umask;
#endif /* SYS_umask */
#ifdef SYS_umount2
if(strcmp("SYS_umount2", name) == 0) return SYS_umount2;
#endif /* SYS_umount2 */
#ifdef SYS_uname
if(strcmp("SYS_uname", name) == 0) return SYS_uname;
#endif /* SYS_uname */
#ifdef SYS_unlink
if(strcmp("SYS_unlink", name) == 0) return SYS_unlink;
#endif /* SYS_unlink */
#ifdef SYS_unlinkat
if(strcmp("SYS_unlinkat", name) == 0) return SYS_unlinkat;
#endif /* SYS_unlinkat */
#ifdef SYS_unshare
if(strcmp("SYS_unshare", name) == 0) return SYS_unshare;
#endif /* SYS_unshare */
#ifdef SYS_ustat
if(strcmp("SYS_ustat", name) == 0) return SYS_ustat;
#endif /* SYS_ustat */
#ifdef SYS_utime
if(strcmp("SYS_utime", name) == 0) return SYS_utime;
#endif /* SYS_utime */
#ifdef SYS_utimensat
if(strcmp("SYS_utimensat", name) == 0) return SYS_utimensat;
#endif /* SYS_utimensat */
#ifdef SYS_utimes
if(strcmp("SYS_utimes", name) == 0) return SYS_utimes;
#endif /* SYS_utimes */
#ifdef SYS_vfork
if(strcmp("SYS_vfork", name) == 0) return SYS_vfork;
#endif /* SYS_vfork */
#ifdef SYS_vhangup
if(strcmp("SYS_vhangup", name) == 0) return SYS_vhangup;
#endif /* SYS_vhangup */
#ifdef SYS_vmsplice
if(strcmp("SYS_vmsplice", name) == 0) return SYS_vmsplice;
#endif /* SYS_vmsplice */
#ifdef SYS_wait4
if(strcmp("SYS_wait4", name) == 0) return SYS_wait4;
#endif /* SYS_wait4 */
#ifdef SYS_waitid
if(strcmp("SYS_waitid", name) == 0) return SYS_waitid;
#endif /* SYS_waitid */
#ifdef SYS_write
if(strcmp("SYS_write", name) == 0) return SYS_write;
#endif /* SYS_write */
#ifdef SYS_writev
if(strcmp("SYS_writev", name) == 0) return SYS_writev;
#endif /* SYS_writev */
return -1;
}
#endif /* SYSCALL_LIST_H_ */
