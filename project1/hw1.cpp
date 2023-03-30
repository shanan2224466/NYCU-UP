#include <pwd.h>
#include <regex>
#include <string>
#include <iomanip>
#include <fstream>
#include <iostream>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

using namespace std;

struct Filter {
    string Comm = "";
    string Type = "";
    string File = "";
};

struct File {
    string COMMAND;
    string PID;
    string USER;
    string FD;
    string TYPE;
    string NODE;
    string NAME;
};

bool is_number(char *name) {
    for (int i = 0; i < strlen(name); i++) {
        if (!isdigit(name[i]))
            return false;
    }
    return true;
}

bool compare(string s, string filter) {
    if (filter == "")
        return true;
    regex re(filter);
    smatch match;
    if (regex_search(s, match, re)) {
        return true;
    }
    return false;
}

void print_result(string COMMAND, string PID, string USER, string FD, string TYPE, string NODE, string NAME) {
    // if (COMMAND.empty() || PID.empty() || USER.empty() || FD.empty() || TYPE.empty() || NODE.empty() || NAME.empty()) {
    //     return;
    // }
    cout << left << setw(5) << COMMAND << right << setw(10) << PID << setw(15) <<
            USER << setw(10) << FD << setw(15) << TYPE << setw(10) << NODE <<
            left << setw(50) << NAME << endl;
}

string get_command(string path) {
    string s;
    ifstream file;
    file.open(path + "/stat");
    getline(file, s);
    file.close();
    regex re(".+\\((.+)\\).+");
    smatch match;
    regex_search(s, match, re);
    return match[1].str();
}

string get_pid(string path) {
    string s;
    ifstream file;
    file.open(path + "/stat");
    getline(file, s);
    file.close();
    regex re("(\\d+)\\s+\\(.+\\).+");
    smatch match;
    regex_search(s, match, re);
    return match[1].str();
}

string get_user(string path) {
    struct stat file_stat;
    struct passwd *pwd;
    if (lstat(path.c_str(), &file_stat) == -1) {
        perror("lstat");
        exit(errno);
    }
    pwd = getpwuid(file_stat.st_uid);
    return pwd->pw_name;
}

string get_type(string path, string dir) {
    string pathname = path + "/" + dir;
    struct stat file_stat;
    if (lstat(pathname.c_str(), &file_stat) == -1) {
        perror("lstat");
        exit(errno);
    }
    if (S_ISLNK(file_stat.st_mode)) {
        // handle symbolic links
        char target[256];
        memset(target, 0, sizeof(target));
        if (readlink(pathname.c_str(), target, sizeof(target)) == -1) {
            return "unknown";
        }
        struct stat target_stat;
        if (lstat(target, &target_stat) == -1) {
            perror("lstat");
            exit(errno);
        }
        file_stat = target_stat;
    }
    switch (file_stat.st_mode & S_IFMT) {
        case S_IFDIR:
            return "DIR";
        case S_IFREG:
            return "REG";
        case S_IFCHR:
            return "CHR";
        case S_IFIFO:
            return "FIFO";
        case S_IFSOCK:
            return "SOCK";
        default:
            return "unknown";
    }
}


string get_name(string path, string dir) {
    string pathname = path + "/" + dir;
    if (dir == "fd") {
        DIR *dir;
        struct dirent *diread;
        if ((dir = opendir(pathname.c_str())) != NULL) {
            while ((diread = readdir(dir)) != NULL) {
                char target[256];
                memset(target, 0, sizeof(target));
                if (readlink((pathname + "/" + diread->d_name).c_str(), target, sizeof(target)) != -1) {
                    return target;
                }
                else {
                    perror("readlink");
                    exit(errno);
                }
            }
            closedir(dir);
        }
        else if (errno == EACCES) {
            return pathname + string(" (opendir: Permission denied)");
        }
        else {
            perror("opendir");
            exit(errno);
        }
    }
    else {
        char target[256];
        memset(target, 0, sizeof(target));
        if (readlink(pathname.c_str(), target, sizeof(target)) != -1) {
            return target;
        }
        else if (errno == EACCES) {
            return pathname + string(" (readlink: Permission denied)");
        }
        else {
            return "";
        }
    }
}

void get_fd(struct Filter filter, struct File file, string path, string fd_dir) {
    if (fd_dir == "cwd") {
        file.FD = "cwd";
        file.NAME = get_name(path, fd_dir);
        file.TYPE = get_type(path, fd_dir);
        print_result(file.COMMAND, file.PID, file.USER, file.FD, file.TYPE, file.NODE, file.NAME);
    }
    else if (fd_dir == "root") {
        file.FD = "rtd";
        file.NAME = get_name(path, fd_dir);
        file.TYPE = get_type(path, fd_dir);
        print_result(file.COMMAND, file.PID, file.USER, file.FD, file.TYPE, file.NODE, file.NAME);
    }
    else if (fd_dir == "exe") {
        file.FD = "txt";
        file.NAME = get_name(path, fd_dir);
        file.TYPE = get_type(path, fd_dir);
        print_result(file.COMMAND, file.PID, file.USER, file.FD, file.TYPE, file.NODE, file.NAME);
    }
    else if (fd_dir == "maps") {
        file.FD = "mem";
        string pathname = path + "/" + fd_dir;
        struct stat file_stat;
        if (lstat(pathname.c_str(), &file_stat) == -1) {
            perror("lstat");
            exit(errno);
        }
        else if (errno == EACCES) {
            return;
        }
        
    }
    else if (fd_dir == "fd") {
        string pathname = path + "/" + fd_dir;
        DIR *dir;
        struct dirent *diread;
        if ((dir = opendir(pathname.c_str())) != NULL) {
            while ((diread = readdir(dir)) != NULL) {
                if (strcmp(diread->d_name, ".") == 0 || strcmp(diread->d_name, "..") == 0) {
                    continue;
                }
                struct stat file_stat;
                if (lstat((pathname + "/" + diread->d_name).c_str(), &file_stat) == -1) {
                    perror("lstat");
                    exit(errno);
                }
                if (((file_stat.st_mode) & S_IRUSR) && ((file_stat.st_mode) & S_IWUSR)){
                    file.FD = string(diread->d_name) + "u";
                }
                else if ((file_stat.st_mode) & S_IRUSR) {
                    file.FD = string(diread->d_name) + "r";
                }
                else if ((file_stat.st_mode) & S_IWUSR) {
                    file.FD = string(diread->d_name) + "w";
                }
                file.NAME = get_name(pathname, diread->d_name);
                file.TYPE = get_type(pathname, diread->d_name);
                print_result(file.COMMAND, file.PID, file.USER, file.FD, file.TYPE, file.NODE, file.NAME);
            }
            closedir(dir);
        }
        else if (errno == EACCES) {
            file.FD = "NOFD";
            file.NODE = "";
            file.TYPE = "";
            file.NAME = get_name(path, fd_dir);
            print_result(file.COMMAND, file.PID, file.USER, file.FD, file.TYPE, file.NODE, file.NAME);
        }
    }
}

void run(struct Filter filter, struct File file, string pathname) {
    string fd_dir[5] = {"cwd", "root", "exe", "maps", "fd"};
    for (int i = 0; i < 5; i++) {
        get_fd(filter, file, pathname, fd_dir[i]);
    }
}

void initial(struct Filter filter) {
    struct File file;
    string path = "/proc/";

    DIR *dir;
    struct dirent *diread;
    if ((dir = opendir(path.c_str())) != NULL) {
        while ((diread = readdir(dir)) != NULL) {
            if (!is_number(diread->d_name)) {
                continue;
            }
            string pathname = path + diread->d_name;
            file.COMMAND = get_command(pathname);
            if (!compare(file.COMMAND, filter.Comm)) {
                continue;
            }
            file.PID     = get_pid(pathname);
            file.USER    = get_user(pathname);
            run(filter, file, pathname);
        }
        closedir(dir);
    }
    else {
        perror("opendir");
        exit(errno);
    }
}

int main(int argc, char* argv[]) {

    regex re("-c\\s+(\\w+)|-t\\s+(\\w+)|-f\\s+(\\w+\\.\\w+)|sudo|-\\w+");
    smatch match;
    string arg = "";
    struct Filter filter;

    for (int i = 1; i < argc; i++) {
        arg += argv[i];
        arg += " ";
    }
    while (regex_search(arg, match, re)) {
        if (regex_search(arg, match, re)) {
            if (match[1].matched) {
                filter.Comm = match[1];
            }
            if (match[2].matched) {
                filter.Type = match[2];
            }
            if (match[3].matched) {
                filter.File = match[3];
            }
            if (match[4].matched) {
                cout << "sudo open: confirmed." << endl;
            }
            if (match[5].matched) {
                cerr << "TypeError: Only allow -c, -t, -f" << endl;
                exit(1);
            }
        }
        arg = match.suffix();
    }
    print_result("COMMAND", "PID  ", "USER  ", "FD  ", "TYPE  ", "NODE   ", "\b\bNAME");
    // cout << "COMMAND" << setw(10) << "PID" << setw(15) <<
    //         "USER" << setw(10) << "FD" << setw(10) <<
    //         "TYPE" << setw(10) << "NODE" << setw(40) <<
    //         "NAME" << endl;

    initial(filter);

    return 0;
}