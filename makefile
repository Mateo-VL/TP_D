CC      = gcc
CFLAGS  = -Wall -g

all: desafio_1 desafio_2

desafio_1: desafio_1.c md5.c md5.h
	$(CC) $(CFLAGS) desafio_1.c md5.c -o desafio_1

desafio_2: desafio_2.c md5.c md5.h
	$(CC) $(CFLAGS) desafio_2.c md5.c -o desafio_2

run2: desafio_2
	./desafio_2

clean:
	rm -f desafio_1 desafio_2

.PHONY: all run2 clean