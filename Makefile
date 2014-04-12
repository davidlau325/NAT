CC=gcc
CFLAGS= -lipq

run:$(CC) -Wall *.c -o nat $(CFLAGS)

.PHONY:clean
clean:
	@rm *.o || (echo "No build file found")
	@rm nat || (echo "No executable found")
	@echo "Build file clean!"
