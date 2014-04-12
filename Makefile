CC=gcc
CFLAGS= -Wall -O3
LDFLAGS= -lipq -lm
DEPS=checksum.h tcp.h
OBJ=nat.o checksum.o tcp.o

%.o:%.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $< $(LDFLAGS)

run:$(OBJ)
	$(CC) $(CFLAGS) -o nat $^ $(LDFLAGS)

.PHONY:clean
clean:
	@rm *.o || (echo "No build file found")
	@rm nat || (echo "No executable found")
	@echo "Build file clean!"
