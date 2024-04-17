#include "libmini.h"

const char *s = "sigalrm is pending.\n";

int main(int argc, char* argv[]) {
	char b[SIZE_MAX];
	ssize_t bytesread = read(STDIN_FILENO, b, strlen(b));
	if (bytesread > 0 && b == '\x03') {
		write(STDOUT_FILENO, s, strlen(s));
	}
	return 0;
}