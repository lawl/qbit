CFLAGS=-std=c99 -Werror -Wall -Wformat -Wformat-security -Werror=format-security -D_FORTIFY_SOURCE=2 -fstack-protector-all -fPIE -pie 
LDFLAGS=
EXEC=qbit_sandbox

all: $(EXEC)

qbit_sandbox: qbit_sandbox.o seccomp.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm *.o $(EXEC)


.PHONY: clean
