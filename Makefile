CFLAGS=-Werror -Wall -Wformat -Wformat-security -Werror=format-security -D_FORTIFY_SOURCE=2 -fstack-protector-all -fPIE -pie -ansi 
LDFLAGS=
EXEC=jchroot

all: $(EXEC)

jchroot: jchroot.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm *.o $(EXEC)


.PHONY: clean
