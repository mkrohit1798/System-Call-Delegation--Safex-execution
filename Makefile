
all: libsafex.so safex delegate

libsafex.so:
	gcc  -Wall -fPIC -shared -g libsafex.c log.c socketcalls.c -o libsafex.so -ldl -D_GNU_SOURCE

safex:
	gcc  -g safex.c -o safex

delegate:
	gcc  -g delegate.c log.c syscalls.c -o delegate -lpthread

clean:
	rm -rf delegate safex libsafex.so *.o *.log

demo:
	gcc test/test_chmod.c -o test/test_chmod.o
	gcc test/test_creat.c -o test/test_creat.o
	gcc test/test_mkdir.c -o test/test_mkdir.o
	gcc test/test_rename.c -o test/test_rename.o
	gcc test/test_rmdir.c -o test/test_rmdir.o
	gcc test/test_truncate.c -o test/test_truncate.o
	gcc test/test_unlink.c -o test/test_unlink.o
	gcc test/untrusted.c -o test/untrusted.o

erase:
	rm -rf test/test_*.o