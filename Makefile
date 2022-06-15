CC = gcc
CFLAGS = -Wall -Wextra -Werror -g -std=c11

RESOLVER_SRC = resolver.c

all: resolver

resolver: $(RESOLVER_SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	$(RM) resolver
