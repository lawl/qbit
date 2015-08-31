#!/usr/bin/env python

with open("/usr/include/x86_64-linux-gnu/bits/syscall.h", "r") as syscalls:
	print "#ifndef SYSCALL_LIST_H_"
	print "#define SYSCALL_LIST_H_"
	print "int syscall_nr_by_name(char *name) {"
	for line in syscalls:
		linear = line.split(" ")
		if len(linear) == 3 and linear[1].startswith("SYS_"):
			print "#ifdef %s" % linear[1]
			print "if(strcmp(\"%s\", name) == 0) return %s;" % (linear[1], linear[1])
			print "#endif /* %s */" % linear[1]
print "return -1;"
print "}"
print "#endif /* SYSCALL_LIST_H_ */"
