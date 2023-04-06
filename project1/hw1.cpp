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
    string Name = "";
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
    for (size_t i = 0; i < strlen(name); i++)
        if (!isdigit(name[i]))
            return false;
    return true;
}

bool compare(string s, string filter) {
    if (filter == "")
        return true;
    regex re(filter);
    smatch match;
    if (regex_search(s, match, re))
        return true;
    return false;
}

void print_result(struct Filter filter, string COMMAND, string PID, string USER, string FD, string TYPE, string NODE, string NAME) {
    /* Except the first time print_result(), the rest need to be filtered. */
    if (PID != "\bPID") {
        regex type(filter.Type);
        regex name(filter.Name);
        if (!filter.Type.empty())
            if (!regex_search(TYPE, type))
                return;

        if (!filter.Name.empty())
            if (!regex_search(NAME, name))
                return;
    }
    cout << left << setw(5) << COMMAND << right << setw(10) << PID << setw(15) <<
            USER << setw(10) << FD << setw(15) << TYPE << setw(20) << NODE <<
            "  " << left << setw(50) << NAME << endl;
}

string get_command(string path) {
    string s;
    ifstream f;
    f.open(path + "/stat");
    getline(f, s);
    f.close();
    /* Read the command from the content inside the parentheses. */
    regex re(".+\\((.+)\\).+");
    smatch match;
    regex_search(s, match, re);
    return match[1].str();
}

string get_pid(string path) {
    string s;
    ifstream f;
    f.open(path + "/stat");
    getline(f, s);
    f.close();
    /* Read from the content before the parentheses. */
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

string get_node(string path, string dir) {
    string pathname = path + "/" + dir;
    struct stat file_stat;
    if (lstat(pathname.c_str(), &file_stat) == -1) {
        perror("lstat");
        exit(errno);
    }
    /* Some of the files are links. Such as root, exe, and cwd. */
    if (S_ISLNK(file_stat.st_mode)) {
        char target[256];
        memset(target, 0, sizeof(target));
        if (readlink(pathname.c_str(), target, sizeof(target)) == -1) {
            return "";
        }
        struct stat target_stat;
        if (lstat(target, &target_stat) == -1) {
            perror("lstat");
            exit(errno);
        }
        file_stat = target_stat;
    }
    return to_string(file_stat.st_ino);
}

string get_type(string path, string dir) {
    string pathname = path + "/" + dir;
    struct stat file_stat;
    if (lstat(pathname.c_str(), &file_stat) == -1) {
        perror("lstat");
        exit(errno);
    }
    /* Some of the files are links. Such as root, exe, and cwd. */
    if (S_ISLNK(file_stat.st_mode)) {
        char target[256];
        memset(target, 0, sizeof(target));
        if (readlink(pathname.c_str(), target, sizeof(target)) == -1)
            return "unknown";

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
                if (readlink((pathname + "/" + diread->d_name).c_str(), target, sizeof(target)) != -1)
                    return target;
                else {
                    perror("readlink");
                    exit(errno);
                }
            }
            closedir(dir);
        }
        else if (errno == EACCES)
            return pathname + string(" (opendir: Permission denied)");
        else {
            perror("opendir");
            exit(errno);
        }
    }
    else {
        char target[256];
        memset(target, 0, sizeof(target));
        if (readlink(pathname.c_str(), target, sizeof(target)) != -1)
            return target;
        else if (errno == EACCES)
            return pathname + string(" (readlink: Permission denied)");
        else
            return "";
    }
    return "";
}

void print_maps(struct Filter filter, struct File file, string path) {
    string s, last_inode;
    ifstream f;
    f.open(path);
    while (getline(f, s)) {
        stringstream ss(s);
        string address, permissions, offset, device, inode, pathname;
        ss >> address >> permissions >> offset >> device >> inode >> pathname;

        if (inode == "0" || last_inode == inode)
            continue;

        file.NODE = inode;
        file.NAME = pathname;
        print_result(filter, file.COMMAND, file.PID, file.USER, file.FD, file.TYPE, file.NODE, file.NAME);
        ss.str("");
        ss.clear();
        last_inode = inode;
    }
    f.close();
}
/* Get the rest of the information: fd, type, inode, and name. */
void run(struct Filter filter, struct File file, string path, string fd_dir) {
    if (fd_dir == "cwd") {
        file.FD = "cwd";
        file.TYPE = get_type(path, fd_dir);
        file.NODE = get_node(path, fd_dir);
        file.NAME = get_name(path, fd_dir);
        print_result(filter, file.COMMAND, file.PID, file.USER, file.FD, file.TYPE, file.NODE, file.NAME);
    }
    else if (fd_dir == "root") {
        file.FD = "rtd";
        file.TYPE = get_type(path, fd_dir);
        file.NODE = get_node(path, fd_dir);
        file.NAME = get_name(path, fd_dir);
        print_result(filter, file.COMMAND, file.PID, file.USER, file.FD, file.TYPE, file.NODE, file.NAME);
    }
    else if (fd_dir == "exe") {
        file.FD = "txt";
        file.TYPE = get_type(path, fd_dir);
        file.NODE = get_node(path, fd_dir);
        file.NAME = get_name(path, fd_dir);
        print_result(filter, file.COMMAND, file.PID, file.USER, file.FD, file.TYPE, file.NODE, file.NAME);
    }
    else if (fd_dir == "maps") {
        file.FD = "mem";
        string pathname = path + "/" + fd_dir;

        struct stat file_stat;
        if (lstat(pathname.c_str(), &file_stat) == -1) {
            perror("lstat");
            exit(errno);
        }
        else if (errno == EACCES)
            return;

        file.TYPE = get_type(path, fd_dir);
        print_maps(filter, file, pathname);
    }
    else if (fd_dir == "fd") {
        string pathname = path + "/" + fd_dir;
        DIR *dir;
        struct dirent *diread;
        if ((dir = opendir(pathname.c_str())) != NULL) {
            while ((diread = readdir(dir)) != NULL) {
                if (strcmp(diread->d_name, ".") == 0 || strcmp(diread->d_name, "..") == 0)
                    continue;

                struct stat file_stat;
                if (lstat((pathname + "/" + diread->d_name).c_str(), &file_stat) == -1) {
                    perror("lstat");
                    exit(errno);
                }

                if (((file_stat.st_mode) & S_IRUSR) && ((file_stat.st_mode) & S_IWUSR))
                    file.FD = string(diread->d_name) + "u";
                else if ((file_stat.st_mode) & S_IRUSR) 
                    file.FD = string(diread->d_name) + "r";
                else if ((file_stat.st_mode) & S_IWUSR) 
                    file.FD = string(diread->d_name) + "w";

                file.TYPE = get_type(pathname, diread->d_name);
                file.NODE = get_node(pathname, diread->d_name);
                file.NAME = get_name(pathname, diread->d_name);
                print_result(filter, file.COMMAND, file.PID, file.USER, file.FD, file.TYPE, file.NODE, file.NAME);
            }
            closedir(dir);
        }
        else if (errno == EACCES) {
            file.FD = "NOFD";
            file.TYPE = "";
            file.NODE = "";
            file.NAME = get_name(path, fd_dir);
            print_result(filter, file.COMMAND, file.PID, file.USER, file.FD, file.TYPE, file.NODE, file.NAME);
        }
    }
}
/* (i) Open the /proc directory and read it. (ii) Get three simple information: command, pid, and user, firstly. */
void initial(struct Filter filter) {
    struct File file;
    string path = "/proc/";
    string fd_dir[5] = {"cwd", "root", "exe", "maps", "fd"};

    DIR *dir;
    struct dirent *diread;
    if ((dir = opendir(path.c_str())) != NULL) {
        while ((diread = readdir(dir)) != NULL) {
            if (!is_number(diread->d_name))
                continue;

            string pathname = path + diread->d_name;
            file.COMMAND = get_command(pathname);
            if (!compare(file.COMMAND, filter.Comm))
                continue;

            file.PID  = get_pid(pathname);
            file.USER = get_user(pathname);
            for (int i = 0; i < 5; i++) {
                run(filter, file, pathname, fd_dir[i]);
            }
        }
        closedir(dir);
    }
    else {
        perror("opendir");
        exit(errno);
    }
}

int main(int argc, char* argv[]) {
    regex re("-c\\s+(\\w+)|-t\\s+(\\w+)|-f\\s+(\\w+)|(-[^ctf])");
    smatch match;
    string arg = "";
    struct Filter filter;

    for (int i = 0; i < argc; i++) {
        arg += argv[i];
        arg += " ";
    }
    while (regex_search(arg, match, re)) {
        if (match[1].matched) {
            filter.Comm = match[1];
            cout << "filter.Comm = " << filter.Comm << endl;}
        if (match[2].matched) {
            filter.Type = match[2];
            cout << "filter.Type = " << filter.Type << endl;}
        if (match[3].matched) {
            filter.Name = match[3];
            cout << "filter.Name = " << filter.Name << endl;}
        if (match[4].matched) {
            cerr << "Invalid input. Usage: ./hw1 [-c REGEX] [-t TYPE] [-f REGEX]" << endl;
            cerr << "-c REGEX :\na regular expression (REGEX) filter for filtering command line." << 
                    "For example -c sh would match bash, zsh, and share." << endl;
            cerr << "-t TYPE  :\na TYPE filter. Valid TYPE includes REG, CHR, DIR, FIFO, SOCK, and unknown." <<
                    "TYPEs other than the listed should be considered invalid." << endl;
            cerr << "-f REGEX :\na regular expression (REGEX) filter for filtering filenames" << endl;
            exit(1);
        }
        arg = match.suffix();
    }
    /* For spec. */
    if (filter.Type != "" && filter.Type != "REG" && filter.Type != "CHR" && filter.Type != "DIR" && 
        filter.Type != "FIFO" && filter.Type != "SOCK" && filter.Type != "unknown") {
        cerr << "Invalid TYPE option." << endl;
        exit(1);
    }
    print_result(filter, "COMMAND", "\bPID", "USER", "FD", "TYPE", "NODE", "NAME");
    initial(filter);
    return 0;
}