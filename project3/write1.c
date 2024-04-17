#include "libmini.h"

const char *s = "Hello world!\n";

int main(int argc, char* argv[]) {
	write(STDOUT_FILENO, s, strlen(s));
	return 0;
}