#include "libmini.h"

const char *s = "sigalrm is pending.\n";

int main(int argc, char* argv[]) {
	sleep(5);
	write(STDOUT_FILENO, s, strlen(s));
	return 0;
}