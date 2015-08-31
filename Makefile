CFLAGS=-std=c99 -Werror -Wall -Wformat -Wformat-security -Werror=format-security -D_FORTIFY_SOURCE=2 -fstack-protector-all -fPIE -pie 
LDFLAGS=
EXEC=jchroot

all: $(EXEC)

jchroot: jchroot.o seccomp.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm *.o $(EXEC)


.PHONY: clean
