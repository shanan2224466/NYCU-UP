#include <iostream>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <cstring>
#include <sys/wait.h>

using namespace std;

int main(int argc, char *argv[]){
    if (argc == 1) {
        cerr << "no command given." << endl;
        exit(EXIT_FAILURE);
    }

    int opt, args_index = 1;
    char file[FILENAME_MAX] = "", sopath[PATH_MAX] = "./logger.so", *args[256];

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            args_index = i + 1;
            break;
        }
    }

    while ((opt = getopt(argc, argv, "o:p:")) != -1) {
        switch (opt) {
        case 'o':
            strcpy(file, optarg);
            setenv("LOGGER_FILE", file, 1);
            break;
        case 'p':
            strcpy(sopath, optarg);
            break;
        case '?':
            cerr << "usage: " << argv[0] << "[-o file] [-p sopath] [--] cmd [cmd args ...]" << endl;
            cerr << "       -p: set the path to logger.so, default = ./logger.so" << endl;
            cerr << "       -o: print output to file, print to \"stderr\" if no file specified" << endl;
            cerr << "       --: separate the arguments for logger and for the command" << endl;
            exit(EXIT_FAILURE);
        }
    }

    for (int i = args_index, j = 0; i < argc; i++) {
        args[j++] = argv[i];
    }
    args[argc - args_index + 1] = NULL;

    if (strcmp(file, "") == 0) {
        int fd = dup(STDERR_FILENO);
        char fd_str[16];
        sprintf(fd_str, "%d", fd);
        setenv("LOGGER_STDERR", fd_str, 1);
    }
    setenv("LD_PRELOAD", sopath, 1);

    int pid;
    if ((pid = fork()) == 0) {
        execvp(args[0], args);
        exit(errno);
    }
    else if (pid > 0) {
        wait(NULL);
    }

    return 0;
}