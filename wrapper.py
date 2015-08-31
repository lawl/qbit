#!/usr/bin/env python

import os

DEFAULT_BLACKLIST = ["SYS_mount", "SYS_umount2", "SYS_ptrace", "SYS_kexec_load", "SYS_open_by_handle_at", "SYS_init_module", "SYS_init_module", "SYS_finit_module", "SYS_delete_module", "SYS_iopl", "SYS_ioperm", "SYS_ni_syscall", "SYS_swapon", "SYS_swapoff", "SYS_syslog", "SYS_process_vm_readv", "SYS_process_vm_writev", "SYS_mknod", "SYS_sysfs", "SYS__sysctl", "SYS_adjtimex", "SYS_clock_adjtime", "SYS_lookup_dcookie", "SYS_perf_event_open", "SYS_fanotify_init", "SYS_kcmp"]


def createFilterListArg(mode, filterlist):
	arg = ""
	for f in filterlist:
		arg+= "-s%s " % f
	return arg

filterarg = createFilterListArg("b", DEFAULT_BLACKLIST)
os.system("./jchroot %s schroot/ /bin/bash" % filterarg)
