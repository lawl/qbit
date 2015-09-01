/*
 * Copyright (c) 2015 lawl
 * Copyright (c) 2011 Vincent Bernat <bernat@luffy.cx>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define _GNU_SOURCE
#define _DEFAULT_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <alloca.h>
#include <errno.h>
#include <sched.h>
#include <pwd.h>
#include <grp.h>
#include <mntent.h>
#include <sys/mount.h>
#include <sys/syscall.h>

#include "qbit_sandbox.h"
#include "seccomp.h"
#include "syscall_list.h"



const char *progname;
static void usage() {
    fprintf(stderr,
            "Usage: %s [OPTIONS] TARGET [--] COMMAND\n"
            "\n"
            "Available options:\n"
            "  -N                              Use a new network namespace\n"
            "  -n NAME       | --hostname=NAME Specify a hostname\n"
            "  -s<SYSCALL>                     Append syscall to filter list\n"
            "  -sc                             Don't use the default syscall blacklist\n"
            "  -sw                             Set syscall filter mode to whitelist\n"
            "  -e NAME=VALUE                   Set an environment variable\n",
            progname);
    exit(EXIT_FAILURE);
}

/* Step 7: Execute command */
static int exec_target(struct config *config) {
    if (execvp(config->command[0], config->command) == -1) {
        int i = 1;
        fprintf(stderr, "unable to execute '%s", config->command[0]);
        while (config->command[i]) fprintf(stderr, " %s", config->command[i++]);
        fprintf(stderr, "': %m\n");
        return errno;
    }
    return EXIT_FAILURE; /* No real return... */
}

/* Step 6: Drop privileges */
static int drop_privileges(struct config *config) {
    if (setgid(getgid()) == -1) {
		fprintf(stderr, "Failed to drop privileges!\n");
		exit(EXIT_FAILURE);
	}
	if (setuid(getuid()) == -1) {
		fprintf(stderr, "Failed to drop privileges!\n");
		exit(EXIT_FAILURE);
	}
    
    /* This may fail on some recent kernels. See
	 * https://lwn.net/Articles/626665/ for the rationale. */
    setgroups(0, NULL);
        

    return 1;
}

/* Step 5: Chroot with pivot_root */
static int changeroot(struct config *config) {
    char *template = NULL;
    if (mount("", "/", "", MS_PRIVATE | MS_REC, "") == -1) {
        fprintf(stderr, "unable to make current root private: %m\n");
        return 0;
    }
    if (mount(config->target, config->target, "bind", MS_BIND|MS_REC, "") == -1) {
        fprintf(stderr, "unable to turn new root into mountpoint: %m\n");
        return 0;
    }
    if (asprintf(&template, "%s/tmp/.pivotrootXXXXXX", config->target) == -1) {
        fprintf(stderr, "unable to allocate template directory: %m\n");
        return 0;
    }
    if (mkdtemp(template) == NULL) {
        fprintf(stderr, "unable to create temporary directory for pivot root: %m\n");
        free(template);
        return 0;
    }
    if (syscall(__NR_pivot_root, config->target, template) == -1) {
        fprintf(stderr, "unable to pivot root to %s: %m\n", config->target);
        rmdir(template);
        free(template);
        return 0;
    }
    if (chdir("/")) {
        fprintf(stderr, "unable to go into chroot: %m\n");
        /* We should cleanup the mount and the temporary directory, but we
         * have pivoted and we won't are likely to still use the old
         * mount... */
        free(template);
        return 0;
    }
    template += strlen(config->target);
    if (umount2(template, MNT_DETACH) == -1) {
        fprintf(stderr, "unable to umount old root: %m\n");
        /* Again, cannot really clean... */
        free(template);
        return 0;
    }
    if (rmdir(template) == -1) {
        fprintf(stderr, "unable to remove directory for old root: %m\n");
        /* ... */
        free(template);
        return 0;
    }
    return 1;
}

/* Step 4: Set hostname */
static void set_hostname(struct config *config) {
    if (config->hostname &&
            sethostname(config->hostname, strlen(config->hostname))) {
        fprintf(stderr, "unable to change hostname to '%s': %m\n",
                config->hostname);
    }
}

/* Step 3: Mount anything needed */
/* actually: entry point after clone() */
static int initialize_child(void *arg) {
	struct config *config = arg;

    
    /* MYTODO: ripped FSTAB parser out, replace with external mounting system */

    set_hostname(config);
    if(!changeroot(config)) {
		return EXIT_FAILURE;
	}
	
	seccomp_filter_enable(config);
	
	if(!drop_privileges(config)) {
		return EXIT_FAILURE;
	}
	
	return exec_target(config);
}

/* Step 1: create a new PID/IPC/NS/UTS namespace */
static int create_namespaces(struct config *config) {
    int ret;
    pid_t pid;

    long stack_size = sysconf(_SC_PAGESIZE);
    void *stack = alloca(stack_size) + stack_size;
    int flags = CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWNS;


    if (config->hostname) flags |= CLONE_NEWUTS;
    if (config->netns) flags |= CLONE_NEWNET;
    pid = clone(initialize_child,
            stack,
            SIGCHLD | flags,
            config);
    if (pid < 0) {
        fprintf(stderr, "failed to clone: %m\n");
        return EXIT_FAILURE;
    }

    while (waitpid(pid, &ret, 0) < 0 && errno == EINTR)
        continue;
    return WIFEXITED(ret)?WEXITSTATUS(ret):EXIT_FAILURE;
}

void parse_filterlist(char *arg, struct config *config) {
	if(arg[0] == 'c') {
		config->filterlist->usedefault=0;
		return;
	}
	if(arg[0] == 'w') {
		config->filterlist->mode='w';
		return;
	}
	int argsyscall = syscall_nr_by_name(arg);
	if(argsyscall != -1) {
		config->filterlist->syscall[config->filterlist->size++]=argsyscall;
	}
}

void parse_config(int argc, char * argv[], struct config *config) {
    int c;
    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            { "hostname", required_argument, 0, 'n' },
            { "help",     no_argument,       0, 'h' },
            { 0,          0,                 0, 0   }
        };

        c = getopt_long(argc, argv, "hNn:e:s:",
                long_options, &option_index);
        if (c == -1) break;

        switch (c) {
            case 'N':
                config->netns = 1;
                break;
            case 's':
				parse_filterlist(optarg, config);            
				break;
            case 'n':
                if (!optarg) usage();
                config->hostname = optarg;
                break;
            case 'e':
                if (!optarg) usage();
                if (putenv(optarg) != 0) {
                    fprintf(stderr, "failed to set environment variable: %s\n", optarg);
                    usage();
                }
                break;
            default:
                usage();
        }
    }
    
	if (optind == argc) usage();
    config->target = argv[optind++];
    if (optind == argc) usage();
    config->command = argv + optind;
}

int main(int argc, char * argv[]) {
    struct config config;
    memset(&config, 0, sizeof(struct config));
    
    struct filterlist filterlist;
    memset(&filterlist, 0, sizeof(struct filterlist));
    filterlist.usedefault=1;
    filterlist.size=0;
    filterlist.mode='b';
    config.filterlist = &filterlist;
    
    progname = argv[0];

    parse_config(argc, argv, &config);

    struct stat st;
    if (stat(config.target, &st) || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "'%s' is not a directory\n", config.target);
        return EXIT_FAILURE;
    }

    return create_namespaces(&config);
}
