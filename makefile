CC      = gcc
CFLAGS  = -Wall -g

desafio_1: desafio_1.c md5.c md5.h
	$(CC) $(CFLAGS) desafio_1.c md5.c -o desafio_1

clean:
	rm -f desafio_1

.PHONY: clean