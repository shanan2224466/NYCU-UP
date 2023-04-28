#include <sys/stat.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>

typedef int (*chmod_t)(const char *, mode_t);
typedef int (*chown_t)(const char *, uid_t, gid_t);
typedef int (*close_t)(int);
typedef int (*creat_t)(const char *, mode_t);
typedef int (*fclose_t)(FILE *);
typedef FILE *  (*fopen_t)(const char *restrict, const char *restrict);
typedef size_t  (*fread_t)(void *restrict, size_t, size_t, FILE *restrict);
typedef size_t  (*fwrite_t)(const void *restrict, size_t, size_t, FILE *restrict);
typedef int     (*open_t)(const char *, int, mode_t);
typedef ssize_t (*read_t)(int, void *, size_t);
typedef int     (*remove_t)(const char *);
typedef int     (*rename_t)(const char *, const char *);
typedef FILE *  (*tmpfile_t)(void);
typedef ssize_t (*write_t)(int, const void *, size_t);

static FILE *file;

#define HOOK_SYSCALL(return_type, syscall_name, syscall_function, ...) \
    static void *syscall_handle = NULL;                                \
    if (!syscall_handle) {                                             \
        syscall_handle = dlopen("libc.so.6", RTLD_LAZY);               \
        if (!syscall_handle) {                                         \
            fprintf(stderr, "Error: %s\n", dlerror());                 \
            exit(1);                                                   \
        }                                                              \
    }                                                                  \
    syscall_function##_t orig_##syscall_function =                     \
        (syscall_function##_t)dlsym(syscall_handle, #syscall_name);    \
    return_type return_value = orig_##syscall_function(__VA_ARGS__);

#define PRINT(format, ...)                                    \
    if (file == NULL) {                                       \
        char *stderr_fd = getenv("LOGGER_STDERR");            \
        if (stderr_fd != NULL) {                              \
            int fd = atoi(stderr_fd);                         \
            file = fdopen(fd, "w");                           \
        }                                                     \
        else {                                                \
            char *file_fd = getenv("LOGGER_FILE");            \
            HOOK_SYSCALL(FILE *, fopen, fopen, file_fd, "w"); \
            file = return_value;                              \
        }                                                     \
    }                                                         \
    fprintf(file, format, __VA_ARGS__);

char *get_resolved_path(const char *pathname) {
    static char resolved_path[PATH_MAX];
    char *real_path = NULL;

    if (realpath(pathname, resolved_path))
        real_path = resolved_path;
    else
        real_path = (char *)pathname;

    return real_path;
}

char *get_realpath_from_fd(int fd) {
    static char real_path[PATH_MAX];

    snprintf(real_path, sizeof(real_path), "/proc/%d/fd/%d", getpid(), fd);
    ssize_t len = readlink(real_path, real_path, sizeof(real_path) - 1);
    real_path[len] = '\0';

    return real_path;
}

char* get_realpath_from_stream(FILE* stream) {
    int fd = fileno(stream);
    static char real_path[PATH_MAX];

    snprintf(real_path, sizeof(real_path), "/proc/%d/fd/%d", getpid(), fd);
    ssize_t len = readlink(real_path, real_path, sizeof(real_path) - 1);
    real_path[len] = '\0';

    return real_path;
}

void *convert_to_character_buffer(const void* ptr, char* character_buffer, size_t bytes_to_read) {
    const char* buffer = (const char*)ptr;
    size_t i;
    for (i = 0; i < bytes_to_read && i < 32; i++) {
        if (isprint(buffer[i])) {
            character_buffer[i] = buffer[i];
        }
        else {
            character_buffer[i] = '.';
        }
    }
    character_buffer[i] = '\0';
}

int chmod(const char *pathname, mode_t mode) {
    HOOK_SYSCALL(int, chmod, chmod, pathname, mode);

    char *real_path = get_resolved_path(pathname);
    PRINT("[logger] chmod(\"%s\", %o) = %d\n", real_path, mode, return_value);

    dlclose(syscall_handle);
    return return_value;
}

int chown(const char *pathname, uid_t owner, gid_t group) {
    HOOK_SYSCALL(int, chown, chown, pathname, owner, group);

    char *real_path = get_resolved_path(pathname);
    PRINT("[logger] chown(\"%s\", %d, %d) = %d\n", real_path, owner, group, return_value);

    dlclose(syscall_handle);
    return return_value;
}

int close(int fd) {
    HOOK_SYSCALL(int, close, close, fd);

    char *real_path = get_realpath_from_fd(fd);
    PRINT("[logger] close(\"%s\") = %d\n", real_path, return_value);

    dlclose(syscall_handle);
    return return_value;
}

int creat(const char *path, mode_t mode) {
    HOOK_SYSCALL(int, creat, creat, path, mode);

    char *real_path = get_resolved_path(path);
    PRINT("[logger] creat(\"%s\", %o) = %d\n", real_path, mode, return_value);

    dlclose(syscall_handle);
    return return_value;
}

int fclose(FILE *stream) {
    HOOK_SYSCALL(int, fclose, fclose, stream);

    char *real_path = get_realpath_from_stream(stream);
    PRINT("[logger] fclose(\"%s\") = %d\n", real_path, return_value);

    dlclose(syscall_handle);
    return return_value;
}

FILE *fopen(const char *restrict pathname, const char *restrict mode) {
    HOOK_SYSCALL(FILE *, fopen, fopen, pathname, mode);

    char *real_path = get_resolved_path(pathname);
    PRINT("[logger] fopen(\"%s\", \"%s\") = %p\n", real_path, mode, return_value);

    dlclose(syscall_handle);
    return return_value;
}

size_t fread(void *restrict ptr, size_t size, size_t nmemb, FILE *restrict stream) {
    HOOK_SYSCALL(size_t, fread, fread, ptr, size, nmemb, stream);

    char *character_buffer;
    character_buffer = convert_to_character_buffer(ptr, character_buffer, size * nmemb);

    char *real_path = get_realpath_from_stream(stream);
    PRINT("[logger] fread(\"%s\", %ld, %ld, \"%s\") = %ld\n", character_buffer, size, nmemb, real_path, return_value);

    dlclose(syscall_handle);
    return return_value;
}

size_t fwrite(const void *restrict ptr, size_t size, size_t nitems, FILE *restrict stream) {
    HOOK_SYSCALL(size_t, fwrite, fwrite, ptr, size, nitems, stream);

    char *character_buffer;
    character_buffer = convert_to_character_buffer(ptr, character_buffer, size * nitems);

    char *real_path = get_realpath_from_stream(stream);
    PRINT("[logger] fread(\"%s\", %ld, %ld, \"%s\") = %ld\n", character_buffer, size, nitems, real_path, return_value);

    dlclose(syscall_handle);
    return return_value;
}

int open(const char *pathname, int flags, mode_t mode) {
    HOOK_SYSCALL(int, open, open, pathname, flags, mode);

    char *real_path = get_resolved_path(pathname);
    PRINT("[logger] open(\"%s\", %o, %o) = %d\n", real_path, flags, mode, return_value);

    dlclose(syscall_handle);
    return return_value;
}

ssize_t read(int fd, void *buf, size_t count) {
    HOOK_SYSCALL(ssize_t, read, read, fd, buf, count);

    char *real_path = get_realpath_from_fd(fd);

    char *character_buffer;
    character_buffer = convert_to_character_buffer(buf, character_buffer, count);
    PRINT("[logger] open(\"%s\", \"%s\", %ld) = %ld\n", real_path, character_buffer, count, return_value);

    dlclose(syscall_handle);
    return return_value;
}

int remove(const char *pathname) {
    HOOK_SYSCALL(int, remove, remove, pathname);

    char *real_path = get_resolved_path(pathname);
    PRINT("[logger] remove(\"%s\") = %d\n", real_path, return_value);

    dlclose(syscall_handle);
    return return_value;
}

int rename(const char *oldpath, const char *newpath) {
    HOOK_SYSCALL(int, rename, rename, oldpath, newpath);

    char *real_old_path, *real_new_path;
    real_old_path = get_resolved_path(oldpath);
    real_new_path = get_resolved_path(newpath);
    PRINT("[logger] chmod(\"%s\", \"%s\") = %d\n", real_old_path, real_new_path, return_value);

    dlclose(syscall_handle);
    return return_value;
}

FILE *tmpfile(void) {
    HOOK_SYSCALL(FILE *, tmpfile, tmpfile);

    PRINT("[logger] tmpfile() = %p\n", return_value);
    dlclose(syscall_handle);
    return return_value;
}

ssize_t write(int fd, const void *buf, size_t count) {
    HOOK_SYSCALL(ssize_t, write, write, fd, buf, count);

    char *real_path = get_realpath_from_fd(fd);

    char *character_buffer;
    character_buffer = convert_to_character_buffer(buf, character_buffer, count);
    PRINT("[logger] open(\"%s\", \"%s\", %ld) = %ld\n", real_path, character_buffer, count, return_value);

    dlclose(syscall_handle);
    return return_value;
}