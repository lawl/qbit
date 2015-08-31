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
#include <sys/prctl.h>
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

#ifndef PATH_MAX
# define PATH_MAX 4096
#endif

struct config {
    int   pipe_fd[2];
    int   netns;
    uid_t user;
    gid_t group;
    char *hostname;
    char *target;
    char *const *command;
};

const char *progname;
static void usage() {
    fprintf(stderr,
            "Usage: %s [OPTIONS] TARGET [--] COMMAND\n"
            "\n"
            "Available options:\n"
            "  -N                         Use a new network namespace\n"
            "  -u USER  | --user=USER     Specify user to use after chroot\n"
            "  -g USER  | --group=USER    Specify group to use after chroot\n"
            "  -n NAME  | --hostname=NAME Specify a hostname\n"
            "  -e NAME=VALUE              Set an environment variable\n",
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

/* Step 6: Drop (or increase) privileges */
static int drop_privileges(struct config *config) {
	/* MYTODO: Always drop privileges, because SUID */
    if (config->group != (gid_t) -1 && setgid(config->group)) {
        fprintf(stderr, "unable to change to GID %d: %m\n", config->group);
        return 0;
    }
    
    /* This may fail on some recent kernels. See
	 * https://lwn.net/Articles/626665/ for the rationale. */
    setgroups(0, NULL);
        
    if (config->user != (uid_t) -1 && setuid(config->user)) {
        fprintf(stderr, "unable to change to UID %d: %m\n", config->user);
        return 0;
    }
#ifdef PR_SET_NO_NEW_PRIVS
    if (config->group != (gid_t) -1 || config->user != (uid_t) -1) {
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    }
#endif
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

void parse_config(int argc, char * argv[], struct config *config) {
    int c;
    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            { "user",     required_argument, 0, 'u' },
            { "group",    required_argument, 0, 'g' },
            { "hostname", required_argument, 0, 'n' },
            { "help",     no_argument,       0, 'h' },
            { 0,          0,                 0, 0   }
        };

        c = getopt_long(argc, argv, "hNUu:g:f:n:M:G:e:",
                long_options, &option_index);
        if (c == -1) break;

        switch (c) {
            case 'N':
                config->netns = 1;
                break;
            case 'u':
                if (!optarg) usage();

                struct passwd *passwd;
                passwd = getpwnam(optarg);
                if (!passwd) {
                    config->user = strtoul(optarg, NULL, 10);
                    if (errno) {
                        fprintf(stderr, "'%s' is not a valid user\n", optarg);
                        usage();
                    }
                } else {
                    config->user = passwd->pw_uid;
                    if (config->group == (gid_t) -1)
                        config->group = passwd->pw_gid;
                }
                break;
            case 'g':
                if (!optarg) usage();

                struct group *group;
                group = getgrnam(optarg);
                if (!group) {
                    config->group = strtoul(optarg, NULL, 10);
                    if (errno) {
                        fprintf(stderr, "'%s' is not a valid group\n", optarg);
                        usage();
                    }
                } else {
                    config->group = group->gr_gid;
                }
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
}

int main(int argc, char * argv[]) {
    struct config config;
    memset(&config, 0, sizeof(struct config));
    config.user = config.group = -1;
    progname = argv[0];

    parse_config(argc, argv, &config);

    if (optind == argc) usage();
    config.target = argv[optind++];
    if (optind == argc) usage();
    config.command = argv + optind;

    struct stat st;
    if (stat(config.target, &st) || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "'%s' is not a directory\n", config.target);
        return EXIT_FAILURE;
    }

    return create_namespaces(&config);
}
