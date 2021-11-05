CC = gcc
CFLAGS = -Wall -Wpedantic -O2
LDFLAGS= -lgmp

all: rsa-meet-in-middle rsa-meet-in-middle-parallelized

rsa-meet-in-middle: rsa-meet-in-middle.c
	$(CC) $(CFLAGS) $(LDFLAGS) rsa-meet-in-middle.c -o rsa-meet-in-middle

rsa-meet-in-middle-parallelized: rsa-meet-in-middle-parallelized.c
	$(CC) $(CFLAGS) $(LDFLAGS) -lpthread rsa-meet-in-middle-parallelized.c -o rsa-meet-in-middle-parallelized

clean:
	rm -f rsa-meet-in-middle rsa-meet-in-middle-parallelized
