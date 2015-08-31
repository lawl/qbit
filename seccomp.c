/*
 * Copyright (c) 2015 lawl
 * Copyright (C) 2014, 2015 netblue30 (netblue30@yahoo.com)
 *
 * This file is part of firejail project
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

/* default seccomp filter
	// seccomp
	struct sock_filter filter[] = {
		VALIDATE_ARCHITECTURE,
		EXAMINE_SYSCALL,
		BLACKLIST(SYS_mount),  // mount/unmount filesystems
		BLACKLIST(SYS_umount2),
		BLACKLIST(SYS_ptrace), // trace processes
		BLACKLIST(SYS_kexec_load), // loading a different kernel
		BLACKLIST(SYS_open_by_handle_at), // open by handle
		BLACKLIST(SYS_init_module), // kernel module handling
#ifdef SYS_finit_module // introduced in 2013
		BLACKLIST(SYS_finit_module),
#endif
		BLACKLIST(SYS_delete_module),
		BLACKLIST(SYS_iopl), // io permisions
#ifdef SYS_ioperm
		BLACKLIST(SYS_ioperm),
#endif
SYS_iopl
		BLACKLIST(SYS_iopl), // io permisions
#endif
#ifdef SYS_ni_syscall), // new io permisions call on arm devices
		BLACKLIST(SYS_ni_syscall),
#endif
		BLACKLIST(SYS_swapon), // swap on/off
		BLACKLIST(SYS_swapoff),
		BLACKLIST(SYS_syslog), // kernel printk control
		RETURN_ALLOW
	};
*/
#include <errno.h>
#include <linux/filter.h>
#include <sys/syscall.h>
#include <linux/capability.h>
#include <linux/audit.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <sys/prctl.h>
#ifndef PR_SET_NO_NEW_PRIVS
# define PR_SET_NO_NEW_PRIVS 38
#endif

#include <linux/seccomp.h>

#include "jchroot.h"


#if defined(__i386__)
# define ARCH_NR	AUDIT_ARCH_I386
#elif defined(__x86_64__)
# define ARCH_NR	AUDIT_ARCH_X86_64
#elif defined(__arm__)
# define ARCH_NR	AUDIT_ARCH_ARM
#else
# warning "Platform does not support seccomp filter yet"
# define ARCH_NR	0
#endif


#define VALIDATE_ARCHITECTURE \
     BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (offsetof(struct seccomp_data, arch))), \
     BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, 1, 0), \
     BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)

#define EXAMINE_SYSCALL BPF_STMT(BPF_LD+BPF_W+BPF_ABS,	\
		 (offsetof(struct seccomp_data, nr)))

#define BLACKLIST(syscall_nr)	\
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, syscall_nr, 0, 1),	\
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)

#define WHITELIST(syscall_nr) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, syscall_nr, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

#define RETURN_ALLOW \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

#define KILL_PROCESS \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)

#define SECSIZE 128 /* initial filter size */
static struct sock_filter *sfilter = NULL;
static int sfilter_alloc_size = 0;
static int sfilter_index = 0;

/* MYTODO: just to make it build */
static int arg_debug=1;
char *arg_seccomp_list_drop = NULL;
char *arg_seccomp_list = NULL;
char *arg_seccomp_list_keep = NULL;


/* debug filter */
void filter_debug(void) {
	/* start filter */
	struct sock_filter filter[] = {
		VALIDATE_ARCHITECTURE,
		EXAMINE_SYSCALL
	};

	/* print sizes */
	printf("SECCOMP Filter:\n");
	if (sfilter == NULL) {
		printf("SECCOMP filter not allocated\n");
		return;
	}
	if (sfilter_index < 4)
		return;
	
	/* test the start of the filter */
	if (memcmp(sfilter, filter, sizeof(filter)) == 0) {
		printf("  VALIDATE_ARCHITECTURE\n");
		printf("  EXAMINE_SYSCAL\n");
	}
	
	/* loop trough blacklists */
	int i = 4;
	while (i < sfilter_index) {
		/* minimal parsing! */
		unsigned char *ptr = (unsigned char *) &sfilter[i];
		int *nr = (int *) (ptr + 4);
		if (*ptr	== 0x15 && *(ptr +14) == 0xff && *(ptr + 15) == 0x7f ) {
			printf("  WHITELIST %d\n", *nr);
			i += 2;
		}
		else if (*ptr	== 0x15 && *(ptr +14) == 0 && *(ptr + 15) == 0) {
			printf("  BLACKLIST %d\n", *nr);
			i += 2;
		}
		else if (*ptr == 0x06 && *(ptr +6) == 0 && *(ptr + 7) == 0 ) {
			printf("  KILL_PROCESS\n");
			i++;
		}
		else if (*ptr == 0x06 && *(ptr +6) == 0xff && *(ptr + 7) == 0x7f ) {
			printf("  RETURN_ALLOW\n");
			i++;
		}
		else {
			printf("  UNKNOWN ENTRY!!!\n");
			i++;
		}
	}
}

/* initialize filter */
static void filter_init(void) {
	if (sfilter) {
		assert(0);
		return;
	}

	if (arg_debug)
		printf("Initialize seccomp filter\n");	
	/* allocate a filter of SECSIZE */
	sfilter = malloc(sizeof(struct sock_filter) * SECSIZE);
	if (!sfilter) {
		perror("malloc");
        exit(EXIT_FAILURE);
    }
	memset(sfilter, 0, sizeof(struct sock_filter) * SECSIZE);
	sfilter_alloc_size = SECSIZE;
	
	/* copy the start entries */
	struct sock_filter filter[] = {
		VALIDATE_ARCHITECTURE,
		EXAMINE_SYSCALL
	};
	sfilter_index = sizeof(filter) / sizeof(struct sock_filter);	
	memcpy(sfilter, filter, sizeof(filter));
}

static void filter_realloc(void) {
	assert(sfilter);
	assert(sfilter_alloc_size);
	assert(sfilter_index);
	if (arg_debug)
		printf("Allocating more seccomp filter entries\n");
	
	/* allocate the new memory */
	struct sock_filter *old = sfilter;
	sfilter = malloc(sizeof(struct sock_filter) * (sfilter_alloc_size + SECSIZE));
	if (!sfilter) {
		perror("malloc");
        exit(EXIT_FAILURE);
    }
	memset(sfilter, 0, sizeof(struct sock_filter) *  (sfilter_alloc_size + SECSIZE));
	
	/* copy old filter */
	memcpy(sfilter, old, sizeof(struct sock_filter) *  sfilter_alloc_size);
	sfilter_alloc_size += SECSIZE;
}

static void filter_add_whitelist(int syscall) {
	assert(sfilter);
	assert(sfilter_alloc_size);
	assert(sfilter_index);
	if (arg_debug)
		printf("Whitelisting syscall %d\n", syscall);
	
	if ((sfilter_index + 2) > sfilter_alloc_size)
		filter_realloc();
	
	struct sock_filter filter[] = {
		WHITELIST(syscall)
	};

	memcpy(&sfilter[sfilter_index], filter, sizeof(filter));
	sfilter_index += sizeof(filter) / sizeof(struct sock_filter);	
}

static void filter_add_blacklist(int syscall) {
	assert(sfilter);
	assert(sfilter_alloc_size);
	assert(sfilter_index);
	if (arg_debug)
		printf("Blacklisting syscall %d\n", syscall);
	
	if ((sfilter_index + 2) > sfilter_alloc_size)
		filter_realloc();
	
	struct sock_filter filter[] = {
		BLACKLIST(syscall)
	};
    
	memcpy(&sfilter[sfilter_index], filter, sizeof(filter));
	sfilter_index += sizeof(filter) / sizeof(struct sock_filter);	
}

static void filter_end_blacklist(void) {
	assert(sfilter);
	assert(sfilter_alloc_size);
	assert(sfilter_index);
	if (arg_debug)
		printf("Ending syscall filter\n");

	if ((sfilter_index + 2) > sfilter_alloc_size)
		filter_realloc();
	
	struct sock_filter filter[] = {
		RETURN_ALLOW
	};

	memcpy(&sfilter[sfilter_index], filter, sizeof(filter));
	sfilter_index += sizeof(filter) / sizeof(struct sock_filter);	
}

static void filter_end_whitelist(void) {
	assert(sfilter);
	assert(sfilter_alloc_size);
	assert(sfilter_index);
	if (arg_debug)
		printf("Ending syscall filter\n");

	if ((sfilter_index + 2) > sfilter_alloc_size)
		filter_realloc();
	
	struct sock_filter filter[] = {
		KILL_PROCESS
	};

	memcpy(&sfilter[sfilter_index], filter, sizeof(filter));
	sfilter_index += sizeof(filter) / sizeof(struct sock_filter);	
}


/* drop filter for seccomp option */
int seccomp_filter_enable(struct config *config) {
	filter_init();
    
    for(int i=0;i<config->filterlist->size;i++) {
        if(config->filterlist->mode == 'w') {
            filter_add_whitelist(config->filterlist->syscall[i]);
        } else {
            filter_add_blacklist(config->filterlist->syscall[i]);
        }
    }
	
    if(config->filterlist->mode == 'w') {
        filter_end_whitelist();
    } else {
        filter_end_blacklist();
    }
	
	if (arg_debug)
		filter_debug();



	struct sock_fprog prog = {
		.len = sfilter_index,
		.filter = sfilter,
	};

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		fprintf(stderr, "Warning: seccomp disabled, it requires a Linux kernel version 3.5 or newer.\n");
		return 1;
	}
	else if (arg_debug) {
		printf("seccomp enabled\n");
	}
	
	return 0;
}

/* keep filter for seccomp option */
int seccomp_filter_keep(void) {
	filter_init();

	/* these 4 syscalls are used by firejail after the seccomp filter is initialized */
	filter_add_whitelist(SYS_setuid);
	filter_add_whitelist(SYS_setgid);
	filter_add_whitelist(SYS_setgroups);
	filter_add_whitelist(SYS_dup);
	
	/* apply keep list */
    
    /*
	if (arg_seccomp_list_keep) {
		if (syscall_check_list(arg_seccomp_list_keep, filter_add_whitelist)) {
			fprintf(stderr, "Error: cannot load seccomp filter\n");
			exit(1);
		}
	}*/
	
	filter_end_whitelist();
	if (arg_debug)
		filter_debug();


	struct sock_fprog prog = {
		.len = sfilter_index,
		.filter = sfilter,
	};

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		fprintf(stderr, "Warning: seccomp disabled, it requires a Linux kernel version 3.5 or newer.\n");
		return 1;
	}
	else if (arg_debug) {
		printf("seccomp enabled\n");
	}
	
	return 0;
}
