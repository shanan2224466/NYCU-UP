CC = gcc
CPP = g++

CFLAGS  = -g -Wall 
LDFLAGS = -ldl
TARGET = logger logger.so

.PHONY: all clean

all: $(TARGET)

logger: hw2.cpp
	$(CPP) $(CFLAGS) $< -o $@

logger.so: so.c
	$(CC) -shared -o $@ -fPIC $< $(LDFLAGS)
clean:
	$(RM) $(TARGET)