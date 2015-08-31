#ifndef SECCOMP_H_
#define SECCOMP_H_
int seccomp_filter_keep(void);
int seccomp_filter_enable(struct config *config);
void filter_debug(void);
extern char *arg_seccomp_list_keep;
extern char *arg_seccomp_list;
extern char *arg_seccomp_list_drop;
#endif /* SECCOMP_H_ */
