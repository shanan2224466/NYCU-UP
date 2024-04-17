#include "libmini.h"

const char *s = "Alarm clock\n";

int main(int argc, char* argv[]) {
	sleep(3);
	write(STDOUT_FILENO, s, strlen(s));
	return 0;
}