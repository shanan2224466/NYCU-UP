#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

typedef int (*chmod_t)(const char *, mode_t);
typedef int (*chown_t)(const char *, uid_t, gid_t);
typedef int (*close_t)(int);
typedef int (*creat_t)(const char *, mode_t);
typedef int (*creat64_t)(const char *, mode_t);
typedef int (*fclose_t)(FILE *);
typedef FILE *  (*fopen_t)(const char *restrict, const char *restrict);
typedef FILE *  (*fopen64_t)(const char *restrict, const char *restrict);
typedef size_t  (*fread_t)(void *restrict, size_t, size_t, FILE *restrict);
typedef size_t  (*fwrite_t)(const void *restrict, size_t, size_t, FILE *restrict);
typedef int     (*open_t)(const char *, int, mode_t);
typedef int     (*open64_t)(const char *, int, mode_t);
typedef ssize_t (*read_t)(int, void *, size_t);
typedef int     (*remove_t)(const char *);
typedef int     (*rename_t)(const char *, const char *);
typedef FILE *  (*tmpfile_t)(void);
typedef FILE *  (*tmpfile64_t)(void);
typedef ssize_t (*write_t)(int, const void *, size_t);

static FILE *file;

#define HOOK_SYSCALL(syscall_function)                                 \
    static void *syscall_handle = NULL;                                \
    if (!syscall_handle) {                                             \
        syscall_handle = dlopen("libc.so.6", RTLD_LAZY);               \
        if (!syscall_handle) {                                         \
            fprintf(stderr, "Error: %s\n", dlerror());                 \
            exit(1);                                                   \
        }                                                              \
    }                                                                  \
    syscall_function##_t orig_##syscall_function =                     \
        (syscall_function##_t)dlsym(syscall_handle, #syscall_function);

#define HOOK_RETURN(return_type, syscall_function, ...)                \
    return_type return_value = orig_##syscall_function(__VA_ARGS__);

#define HOOK_PRINT(format, ...)                      \
    if (file == NULL) {                              \
        char *stderr_fd = getenv("LOGGER_STDERR");   \
        if (stderr_fd != NULL) {                     \
            int fd = atoi(stderr_fd);                \
            file = fdopen(fd, "w");                  \
        }                                            \
        else {                                       \
            char *file_fd = getenv("LOGGER_FILE");   \
            HOOK_SYSCALL(fopen);                     \
            HOOK_RETURN(FILE *, fopen, file_fd, "w") \
            file = return_value;                     \
        }                                            \
    }                                                \
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

char* get_realpath_from_stream(FILE *stream) {
    int fd = fileno(stream);
    char fd_path[PATH_MAX];
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
        if (isprint(buffer[i]))
            character_buffer[i] = buffer[i];
        else
            character_buffer[i] = '.';
    }
    character_buffer[i] = '\0';
}

int chmod(const char *pathname, mode_t mode) {
    HOOK_SYSCALL(chmod);

    char *real_path = get_resolved_path(pathname);
    HOOK_RETURN(int, chmod, pathname, mode);
    HOOK_PRINT("[logger] %s(\"%s\", %o) = %d\n", __func__, real_path, mode, return_value);

    return return_value;
}

int chown(const char *pathname, uid_t owner, gid_t group) {
    HOOK_SYSCALL(chown);

    char *real_path = get_resolved_path(pathname);
    HOOK_RETURN(int, chown, pathname, owner, group);
    HOOK_PRINT("[logger] %s(\"%s\", %d, %d) = %d\n", __func__, real_path, owner, group, return_value);

    return return_value;
}

int close(int fd) {
    HOOK_SYSCALL(close);

    char *real_path = get_realpath_from_fd(fd);
    HOOK_RETURN(int, close, fd);
    HOOK_PRINT("[logger] %s(\"%s\") = %d\n", __func__, real_path, return_value);

    return return_value;
}

int creat(const char *path, mode_t mode) {
    HOOK_SYSCALL(creat);

    char *real_path = get_resolved_path(path);
    HOOK_RETURN(int, creat, path, mode);
    HOOK_PRINT("[logger] %s(\"%s\", %o) = %d\n", __func__, real_path, mode, return_value);

    return return_value;
}

int creat64(const char *path, mode_t mode) {
    HOOK_SYSCALL(creat64);

    char *real_path = get_resolved_path(path);
    HOOK_RETURN(int, creat64, path, mode);
    HOOK_PRINT("[logger] %s(\"%s\", %o) = %d\n", __func__, real_path, mode, return_value);

    return return_value;
}

int fclose(FILE *stream) {
    HOOK_SYSCALL(fclose);

    char *real_path = get_realpath_from_stream(stream);
    HOOK_RETURN(int, fclose, stream);
    HOOK_PRINT("[logger] %s(\"%s\") = %d\n", __func__, real_path, return_value);

    return return_value;
}

FILE *fopen(const char *restrict pathname, const char *restrict mode) {
    HOOK_SYSCALL(fopen);

    char *real_path = get_resolved_path(pathname);
    HOOK_RETURN(FILE *, fopen, pathname, mode);
    HOOK_PRINT("[logger] %s(\"%s\", \"%s\") = %p\n", __func__, real_path, mode, return_value);

    return return_value;
}

FILE *fopen64(const char *restrict pathname, const char *restrict mode) {
    HOOK_SYSCALL(fopen64);

    char *real_path = get_resolved_path(pathname);
    HOOK_RETURN(FILE *, fopen64, pathname, mode);
    HOOK_PRINT("[logger] %s(\"%s\", \"%s\") = %p\n", __func__, real_path, mode, return_value);

    return return_value;
}

size_t fread(void *restrict ptr, size_t size, size_t nmemb, FILE *restrict stream) {
    HOOK_SYSCALL(fread);

    char *real_path = get_realpath_from_stream(stream);
    char *character_buffer = convert_to_character_buffer(ptr, character_buffer, size * nmemb);
    HOOK_RETURN(size_t, fread, ptr, size, nmemb, stream);
    HOOK_PRINT("[logger] %s(\"%s\", %ld, %ld, \"%s\") = %ld\n", __func__, character_buffer, size, nmemb, real_path, return_value);

    return return_value;
}

size_t fwrite(const void *restrict ptr, size_t size, size_t nitems, FILE *restrict stream) {
    HOOK_SYSCALL(fwrite);

    char *real_path = get_realpath_from_stream(stream);
    char *character_buffer = convert_to_character_buffer(ptr, character_buffer, size * nitems);
    HOOK_RETURN(size_t, fwrite, ptr, size, nitems, stream);
    HOOK_PRINT("[logger] %s(\"%s\", %ld, %ld, \"%s\") = %ld\n", __func__, character_buffer, size, nitems, real_path, return_value);

    return return_value;
}

int open(const char *pathname, int flags, mode_t mode) {
    HOOK_SYSCALL(open);

    char *real_path = get_resolved_path(pathname);
    HOOK_RETURN(int, open, pathname, flags, mode);
    HOOK_PRINT("[logger] %s(\"%s\", %o, %o) = %d\n", __func__, real_path, flags, mode, return_value);

    return return_value;
}

int open64(const char *pathname, int flags, mode_t mode) {
    HOOK_SYSCALL(open64);

    char *real_path = get_resolved_path(pathname);
    HOOK_RETURN(int, open64, pathname, flags, mode);
    HOOK_PRINT("[logger] %s(\"%s\", %o, %o) = %d\n", __func__, real_path, flags, mode, return_value);

    return return_value;
}

ssize_t read(int fd, void *buf, size_t count) {
    HOOK_SYSCALL(read);

    char *real_path = get_realpath_from_fd(fd);
    char *character_buffer = convert_to_character_buffer(buf, character_buffer, count);
    HOOK_RETURN(ssize_t, read, fd, buf, count);
    HOOK_PRINT("[logger] %s(\"%s\", \"%s\", %ld) = %ld\n", __func__, real_path, character_buffer, count, return_value);

    return return_value;
}

int remove(const char *pathname) {
    HOOK_SYSCALL(remove);

    char *real_path = get_resolved_path(pathname);
    HOOK_RETURN(int, remove, pathname);
    HOOK_PRINT("[logger] %s(\"%s\") = %d\n", __func__, real_path, return_value);

    return return_value;
}

int rename(const char *oldpath, const char *newpath) {
    HOOK_SYSCALL(rename);

    char *real_old_path, *real_new_path;
    real_old_path = get_resolved_path(oldpath);
    real_new_path = get_resolved_path(newpath);
    HOOK_RETURN(int, rename, oldpath, newpath);
    HOOK_PRINT("[logger] %s(\"%s\", \"%s\") = %d\n", __func__, real_old_path, real_new_path, return_value);

    return return_value;
}

FILE *tmpfile(void) {
    HOOK_SYSCALL(tmpfile);
    HOOK_RETURN(FILE *, tmpfile);
    HOOK_PRINT("[logger] %s() = %p\n", __func__, return_value);

    return return_value;
}

FILE *tmpfile64(void) {
    HOOK_SYSCALL(tmpfile64);
    HOOK_RETURN(FILE *, tmpfile64);
    HOOK_PRINT("[logger] %s() = %p\n", __func__, return_value);

    return return_value;
}

ssize_t write(int fd, const void *buf, size_t count) {
    HOOK_SYSCALL(write);

    char *real_path = get_realpath_from_fd(fd);
    char *character_buffer = convert_to_character_buffer(buf, character_buffer, count);
    HOOK_RETURN(ssize_t, write, fd, buf, count);
    HOOK_PRINT("[logger] %s(\"%s\", \"%s\", %ld) = %ld\n", __func__, real_path, character_buffer, count, return_value);

    return return_value;
}