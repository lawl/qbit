#ifndef QBIT_H_
#define QBIT_H_

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
    int   allowptrace;
    char *hostname;
    char *target;
    char *const *command;
    struct filterlist *filterlist;
};

#endif /* QBIT_H_ */
