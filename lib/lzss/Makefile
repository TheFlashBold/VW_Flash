$(info $(SHELL))

# Makefile for lzss
CC = gcc
LD = gcc
CFLAGS = -O2 -Wall -ansi -c
LDFLAGS = -O2 -o

# Treat NT and non-NT windows the same
ifeq ($(OS),Windows_NT)
	OS = Windows
endif

ifeq ($(OS),Windows)
	EXE = .exe
	DEL = del
	OBJS = lzss.o getopt.o
else	#assume Linux/Unix
	EXE =
	DEL = rm
	OBJS = lzss.o
endif

all:		lzss$(EXE)

lzss$(EXE):	$(OBJS)
		$(LD) $^ $(LDFLAGS) $@

lzss.o:		lzss.c
		$(CC) $(CFLAGS) $<

getopt.o:	getopt.c getopt.h
		$(CC) $(CFLAGS) $<

clean:
		$(DEL) *.o
		$(DEL) lzss$(EXE)
