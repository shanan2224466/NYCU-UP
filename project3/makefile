CC = gcc
LD = ld
ASM = yasm

CCFLAGS = -c -g -Wall -fno-stack-protector
LDFLAGS = -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2
ASMFLAGS = -f elf64 -DYASM -D__x86_64__ -DPIC

OBJECTS = start.o libmini64.o
PROGRAMS = write1 alarm1 alarm2 alarm3 jmp1

.PHONY: all clean

all: libmini.so start.o

%.o: %.asm
	$(ASM) $(ASMFLAGS) $< -o $@

libmini.so: libmini64.o libmini.c
	$(CC) $(CCFLAGS) -fPIC -nostdlib libmini.c -o libmini.o
	$(LD) -shared -o $@ libmini64.o libmini.o

test: test.c start.o
	$(CC) $(CCFLAGS) $< -o test.o
	$(LD) $(LDFLAGS) -o $@ test.o start.o -L. -L.. -lmini

%: %.c start.o
	$(CC) $(CCFLAGS) -nostdlib -I. -I.. -DUSEMINI $< -o $*.o
	$(LD) $(LDFLAGS) -o $@ $*.o start.o -L. -L.. -lmini
	rm $*.o

clean:
	rm -f *.o $(OBJECTS) *.so $(PROGRAMS) test.o test
