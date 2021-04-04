CC= gcc

build: libso_stdio.so

libso_stdio.so: libso_stdio.o
	$(CC) -shared libso_stdio.o -o libso_stdio.so

libso_stdio.o: libso_stdio.c
	$(CC) -fPIC -c libso_stdio.c

clean:
	rm -f *.o *.so

.PHONY: clean