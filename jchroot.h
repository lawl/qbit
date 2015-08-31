#ifndef JCHROOT_H_
#define JCHROOT_H_

#ifndef PATH_MAX
# define PATH_MAX 4096
#endif

/* too lazy to realloc stuff */
#define FILTER_MAXSIZE 500

struct filterlist {
	int size;
	int syscall[FILTER_MAXSIZE];
	char mode;
	int usedefault;
};
struct config {
    int   netns;
    char *hostname;
    char *target;
    char *const *command;
    struct filterlist *filterlist;
};

#endif /* JCHROOT_H_ */
