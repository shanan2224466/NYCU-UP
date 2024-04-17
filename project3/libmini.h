#ifndef __LIBMINI_H__
#define __LIBMINI_H__		/* avoid reentrant */

typedef int pid_t;
typedef int uid_t;
typedef unsigned long sigset_t;
typedef unsigned int dev_t;
typedef unsigned int ino_t;
typedef int mode_t;
typedef unsigned int nlink_t;
typedef int gid_t;
typedef unsigned int blksize_t;
typedef long long ssize_t;
typedef long long int blkcnt_t;
typedef long long int time_t;
typedef long long off_t;
typedef unsigned short umode_t;
typedef long long size_t;
typedef void (*sighandler_t)(int);

extern long errno;

#define	NULL		((void*) 0)

union sigval {
	int sival_int;
	void *sival_ptr;
};

typedef struct {
	int si_signo;
	int si_code;
	union sigval si_value;
	int si_errno;
	pid_t si_pid;
	uid_t si_uid;
	void *si_addr;
	int si_status;
	int si_band;
} siginfo_t;

struct timespec {
	long	tv_sec;		/* seconds */
	long	tv_nsec;	/* nanoseconds */
};

struct timeval {
	long	tv_sec;		/* seconds */
	long	tv_usec;	/* microseconds */
};

struct timezone {
	int	tz_minuteswest;	/* minutes west of Greenwich */
	int	tz_dsttime;	/* type of DST correction */
};

typedef struct jmp_buf_s {
   long long reg[8];
   sigset_t mask;
} jmp_buf[1];

struct sigaction{
   void     (*sa_handler)(int);
   void     (*sa_sigaction)(int, siginfo_t *, void *);
   sigset_t   sa_mask;
   int        sa_flags;
   void     (*sa_restorer)(void);
};

typedef struct {
   dev_t     st_dev;     /* ID of device containing file */
   ino_t     st_ino;     /* inode number */
   mode_t    st_mode;    /* protection */
   nlink_t   st_nlink;   /* number of hard links */
   uid_t     st_uid;     /* user ID of owner */
   gid_t     st_gid;     /* group ID of owner */
   dev_t     st_rdev;    /* device ID (if special file) */
   off_t     st_size;    /* total size, in bytes */
   blksize_t st_blksize; /* blocksize for file system I/O */
   blkcnt_t  st_blocks;  /* number of 512B blocks allocated */
   time_t    st_atime;   /* time of last access */
   time_t    st_mtime;   /* time of last modification */
   time_t    st_ctime;   /* time of last status change */
} stat;

typedef void (*sighandler_t)(int);

#define SIZE_MAX 65535

#define S_IFMT   0170000
#define S_IFSOCK 0140000
#define S_IFLNK  0120000
#define S_IFREG  0100000
#define S_IFBLK  0060000
#define S_IFDIR  0040000
#define S_IFCHR  0020000
#define S_IFIFO  0010000
#define S_ISUID  0004000
#define S_ISGID  0002000
#define S_ISVTX  0001000

#define S_ISLNK(m)      (((m) & S_IFMT) == S_IFLNK)
#define S_ISREG(m)      (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)      (((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m)      (((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m)      (((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m)     (((m) & S_IFMT) == S_IFIFO)
#define S_ISSOCK(m)     (((m) & S_IFMT) == S_IFSOCK)

#define S_IRWXU 00700   /* mask for file owner permissions */
#define S_IRUSR 00400   /* owner has read permission */
#define S_IWUSR 00200   /* owner has write permission */
#define S_IXUSR 00100   /* owner has execute permission */

#define S_IRWXG 00070   /* mask for group permissions */
#define S_IRGRP 00040   /* group has read permission */
#define S_IWGRP 00020   /* group has write permission */
#define S_IXGRP 00010   /* group has execute permission */

#define S_IRWXO 00007   /* mask for permissions for others (not in group) */
#define S_IROTH 00004   /* others have read permission */
#define S_IWOTH 00002   /* others have write permission */
#define S_IXOTH 00001   /* others have execute permission */

#define F_ULOCK 0        /* Unlock a previously locked region.  */
#define F_LOCK  1        /* Lock a region for exclusive use.  */
#define F_TLOCK 2        /* Test and lock a region for exclusive use.  */
#define F_TEST  3        /* Test a region for other processes locks.  */

/* from /usr/include/asm-generic/fcntl.h */
#define O_ACCMODE    00000003
#define O_RDONLY	   00000000  /* Open for writing only      */
#define O_WRONLY	   00000001  /* Open for reading and writing */
#define O_RDWR		   00000002  /* Open for reading and writing */
#ifndef O_CREAT
#define O_CREAT		00000100	 /* not fcntl */
#endif
#ifndef O_EXCL
#define O_EXCL       00000200	 /* not fcntl */
#endif
#ifndef O_NOCTTY
#define O_NOCTTY     00000400	 /* not fcntl */
#endif
#ifndef O_TRUNC
#define O_TRUNC		00001000	 /* not fcntl */
#endif
#ifndef O_APPEND
#define O_APPEND     00002000  /* Set file offset to end before each write */
#endif
#ifndef O_NONBLOCK
#define O_NONBLOCK	00004000  /* Non-blocking mode          */
#endif
#ifndef O_DSYNC
#define O_DSYNC		00010000  /* used to be O_SYNC, see below */
#endif
#ifndef FASYNC
#define FASYNC       00020000  /* fcntl, for BSD compatibility */
#endif
#ifndef O_DIRECT
#define O_DIRECT     00040000	 /* direct disk access hint */
#endif
#ifndef O_LARGEFILE
#define O_LARGEFILE	00100000
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY	00200000	 /* must be a directory */
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW	00400000	 /* don't follow links */
#endif
#ifndef O_NOATIME
#define O_NOATIME    01000000
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC    02000000	 /* set close_on_exec */
#endif

/* from /usr/include/bits/fcntl.h */
#define O_DIRECTORY    00200000  /* Must be a directory        */

#define F_DUPFD       0       /* Duplicate file descriptor */
#define F_GETFD       1       /* Get file descriptor flags */
#define F_SETFD       2       /* Set file descriptor flags */
#define F_GETFL       3       /* Get file status flags */
#define F_SETFL       4       /* Set file status flags */
#define F_GETOWN      5       /* Get asynchronous I/O owner */
#define F_SETOWN      6       /* Set asynchronous I/O owner */
#define F_GETLK       7       /* Get record locking information */
#define F_SETLK       8       /* Set record locking information */
#define F_SETLKW      9       /* Set record locking information; wait if blocked */
#define F_GETOWN_EX  10       /* Get owner (process receiving SIGIO/SIGURG) */
#define F_SETOWN_EX  11       /* Set owner (process receiving SIGIO/SIGURG) */

/* from /usr/include/x86_64-linux-gnu/asm/signal.h */
#define SIGHUP                  1
#define SIGINT                  2
#define SIGQUIT                 3
#define SIGILL                  4
#define SIGTRAP                 5
#define SIGABRT                 6
#define SIGIOT                  6
#define SIGBUS                  7
#define SIGFPE                  8
#define SIGKILL                 9
#define SIGUSR1                10
#define SIGSEGV                11
#define SIGUSR2                12
#define SIGPIPE                13
#define SIGALRM                14
#define SIGTERM                15
#define SIGSTKFLT              16
#define SIGCHLD                17
#define SIGCONT                18
#define SIGSTOP                19
#define SIGTSTP                20
#define SIGTTIN                21
#define SIGTTOU                22
#define SIGURG                 23
#define SIGXCPU                24
#define SIGXFSZ                25
#define SIGVTALRM              26
#define SIGPROF                27
#define SIGWINCH               28
#define SIGIO                  29
#define SIGPOLL                SIGIO
/*
#define SIGLOST                29
*/
#define SIGPWR                 30
#define SIGSYS                 31
#define SIGUNUSED              31

/* These should not be considered constants from userland.  */
#define SIGRTMIN               32
#define SIGRTMAX               _NSIG
#define NSIG                   32

#define _NSIG		64
#define _NSIG_BPW	64
#define _NSIG_WORDS	(_NSIG / _NSIG_BPW)

#define SIG_ERR (void (*)())-1
#define SIG_DFL (void (*)())0
#define SIG_IGN (void (*)())1

/* from /usr/include/x86_64-linux-gnu/bits/sigaction.h */
// #define SA_NOCLDSTOP  1		 /* Don't send SIGCHLD when children stop.  */
// #define SA_NOCLDWAIT  2		 /* Don't create zombie on child death.  */
// #define SA_SIGINFO    4		 /* Invoke signal-catching function with three arguments instead of one.  */

// # define SA_ONSTACK   0x08000000 /* Use signal stack by using `sa_restorer'. */
// # define SA_RESTART   0x10000000 /* Restart syscall on signal return.  */
// # define SA_INTERRUPT 0x20000000 /* Historical no-op.  */
// # define SA_NODEFER   0x40000000 /* Don't automatically block the signal when its handler is being executed.  */
// # define SA_RESETHAND 0x80000000 /* Reset to SIG_DFL on entry to handler.  */

#define	SIG_BLOCK     0		 /* Block signals.  */
#define	SIG_UNBLOCK   1		 /* Unblock signals.  */
#define	SIG_SETMASK   2		 /* Set the set of blocked signals.  */

/*
 * SA_FLAGS values:
 *
 * SA_ONSTACK indicates that a registered stack_t will be used.
 * SA_RESTART flag to get restarting signals (which were the default long ago)
 * SA_NOCLDSTOP flag to turn off SIGCHLD when children stop.
 * SA_RESETHAND clears the handler when the signal is delivered.
 * SA_NOCLDWAIT flag on SIGCHLD to inhibit zombies.
 * SA_NODEFER prevents the current signal from being masked in the handler.
 *
 * SA_ONESHOT and SA_NOMASK are the historical Linux names for the Single
 * Unix names RESETHAND and NODEFER respectively.
 */
#define SA_NOCLDSTOP        0x00000001u
#define SA_NOCLDWAIT        0x00000002u
#define SA_SIGINFO          0x00000004u
#define SA_ONSTACK          0x08000000u
#define SA_RESTART          0x10000000u
#define SA_NODEFER          0x40000000u
#define SA_RESETHAND        0x80000000u

#define SA_NOMASK         SA_NODEFER
#define SA_ONESHOT        SA_RESETHAND
#define SA_RESTORER         0x04000000

/* sigaltstack controls */
#define SS_ONSTACK         1
#define SS_DISABLE         2
#define MINSIGSTKSZ        2048
#define SIGSTKSZ           8192

/* Standard file descriptors.  */
#define STDIN_FILENO         0        /* Standard input.  */
#define STDOUT_FILENO        1        /* Standard output.  */
#define STDERR_FILENO        2        /* Standard error output.  */

/* Values for the second argument to access.
   These may be OR'd together.  */
#define R_OK        4                /* Test for read permission.  */
#define W_OK        2                /* Test for write permission.  */
#define X_OK        1                /* Test for execute permission.  */
#define F_OK        0                /* Test for existence.  */

/* Values for the WHENCE argument to lseek.  */
# define SEEK_SET        0        /* Seek from beginning of file.  */
# define SEEK_CUR        1        /* Seek from current position.  */
# define SEEK_END        2        /* Seek from end of file.  */

/* from /usr/include/asm/errno.h */
#define EPERM             1    /* Not super-user */
#define ENOENT            2    /* No such file or directory */
#define ESRCH             3    /* No such process */
#define EINTR             4    /* Interrupted system call */
#define EIO               5    /* I/O error */
#define ENXIO             6    /* No such device or address */
#define E2BIG             7    /* Arg list too long */
#define ENOEXEC           8    /* Exec format error */
#define EBADF             9    /* Bad file number */
#define ECHILD           10    /* No children */
#define EAGAIN           11    /* No more processes */
#define ENOMEM           12    /* Not enough core */
#define EACCES           13    /* Permission denied */
#define EFAULT           14    /* Bad address */
#define ENOTBLK          15    /* Block device required */
#define EBUSY            16    /* Mount device busy */
#define EEXIST           17    /* File exists */
#define EXDEV            18    /* Cross-device link */
#define ENODEV           19    /* No such device */
#define ENOTDIR          20    /* Not a directory */
#define EISDIR           21    /* Is a directory */
#define EINVAL           22    /* Invalid argument */
#define ENFILE           23    /* Too many open files in system */
#define EMFILE           24    /* Too many open files */
#define ENOTTY           25    /* Not a typewriter */
#define ETXTBSY          26    /* Text file busy */
#define EFBIG            27    /* File too large */
#define ENOSPC           28    /* No space left on device */
#define ESPIPE           29    /* Illegal seek */
#define EROFS            30    /* Read only file system */
#define EMLINK           31    /* Too many links */
#define EPIPE            32    /* Broken pipe */
#define EDOM             33    /* Math arg out of domain of func */
#define ERANGE           34    /* Math result not representable */
#define ENOMSG           35    /* No message of desired type */
#define EIDRM            36    /* Identifier removed */
#define ECHRNG           37    /* Channel number out of range */
#define EL2NSYNC         38    /* Level 2 not synchronized */
#define EL3HLT           39    /* Level 3 halted */
#define EL3RST           40    /* Level 3 reset */
#define ELNRNG           41    /* Link number out of range */
#define EUNATCH          42    /* Protocol driver not attached */
#define ENOCSI           43    /* No CSI structure available */
#define EL2HLT           44    /* Level 2 halted */
#define EDEADLK          45    /* Deadlock condition */
#define ENOLCK           46    /* No record locks available */
#define EBADE            50    /* Invalid exchange */
#define EBADR            51    /* Invalid request descriptor */
#define EXFULL           52    /* Exchange full */
#define ENOANO           53    /* No anode */
#define EBADRQC          54    /* Invalid request code */
#define EBADSLT          55    /* Invalid slot */
#define EDEADLOCK        56    /* File locking deadlock error */
#define EBFONT           57    /* Bad font file fmt */
#define ENOSTR           60    /* Device not a stream */
#define ENODATA          61    /* No data (for no delay io) */
#define ETIME            62    /* Timer expired */
#define ENOSR            63    /* Out of streams resources */
#define ENONET           64    /* Machine is not on the network */
#define ENOPKG           65    /* Package not installed */
#define EREMOTE          66    /* The object is remote */
#define ENOLINK          67    /* The link has been severed */
#define EADV             68    /* Advertise error */
#define ESRMNT           69    /* Srmount error */
#define ECOMM            70    /* Communication error on send */
#define EPROTO           71    /* Protocol error */
#define EMULTIHOP        74    /* Multihop attempted */
#define ELBIN            75    /* Inode is remote (not really error) */
#define EDOTDOT          76    /* Cross mount point (not really error) */
#define EBADMSG          77    /* Trying to read unreadable message */
#define EFTYPE           79    /* Inappropriate file type or format */
#define ENOTUNIQ         80    /* Given log. name not unique */
#define EBADFD           81    /* f.d. invalid for this operation */
#define EREMCHG          82    /* Remote address changed */
#define ELIBACC          83    /* Can't access a needed shared lib */
#define ELIBBAD          84    /* Accessing a corrupted shared lib */
#define ELIBSCN          85    /* .lib section in a.out corrupted */
#define ELIBMAX          86    /* Attempting to link in too many libs */
#define ELIBEXEC         87    /* Attempting to exec a shared library */
#define ENOSYS           88   /* Function not implemented */
#define ENMFILE          89   /* No more files */
#define ENOTEMPTY        90   /* Directory not empty */
#define ENAMETOOLONG     91   /* File or path name too long */
#define ELOOP            92   /* Too many symbolic links */
#define EOPNOTSUPP       95   /* Operation not supported on transport endpoint */
#define EPFNOSUPPORT     96   /* Protocol family not supported */
#define ECONNRESET      104   /* Connection reset by peer */
#define ENOBUFS         105   /* No buffer space available */
#define EAFNOSUPPORT    106   /* Address family not supported by protocol family */
#define EPROTOTYPE      107   /* Protocol wrong type for socket */
#define ENOTSOCK        108   /* Socket operation on non-socket */
#define ENOPROTOOPT     109   /* Protocol not available */
#define ESHUTDOWN       110   /* Can't send after socket shutdown */
#define ECONNREFUSED    111   /* Connection refused */
#define EADDRINUSE      112   /* Address already in use */
#define ECONNABORTED    113   /* Connection aborted */
#define ENETUNREACH     114   /* Network is unreachable */
#define ENETDOWN        115   /* Network interface is not configured */
#define ETIMEDOUT       116   /* Connection timed out */
#define EHOSTDOWN       117   /* Host is down */
#define EHOSTUNREACH    118   /* Host is unreachable */
#define EINPROGRESS     119   /* Connection already in progress */
#define EALREADY        120   /* Socket already connected */
#define EDESTADDRREQ    121   /* Destination address required */
#define EMSGSIZE        122   /* Message too long */
#define EPROTONOSUPPORT 123 /* Unknown protocol */
#define ESOCKTNOSUPPORT 124 /* Socket type not supported */
#define EADDRNOTAVAIL   125   /* Address not available */
#define ENETRESET       126
#define EISCONN         127   /* Socket is already connected */
#define ENOTCONN        128   /* Socket is not connected */
#define ETOOMANYREFS    129
#define EPROCLIM        130
#define EUSERS          131
#define EDQUOT          132
#define ESTALE          133
#define ENOTSUP         134   /* Not supported */
#define ENOMEDIUM       135   /* No medium (in tape drive) */
#define ENOSHARE        136   /* No such host or network path */
#define ECASECLASH      137   /* Filename exists with different case */
#define EILSEQ          138
#define EOVERFLOW       139   /* Value too large for defined data type */
#define EWOULDBLOCK     EAGAIN /* Operation would block */

/* system calls */
long sys_read(int fd, char *buf, size_t count);
long sys_write(int fd, const void *buf, size_t count);
long sys_open(const char *filename, int flags, ... /*mode*/);
long sys_close(unsigned int fd);
long sys_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off);
long sys_mprotect(void *addr, size_t len, int prot);
long sys_munmap(void *addr, size_t len);
long sys_pipe(int *filedes);
long sys_dup(int filedes);
long sys_dup2(int oldfd, int newfd);
long sys_pause();
long sys_nanosleep(struct timespec *rqtp, struct timespec *rmtp);
long sys_fork(void);
long sys_exit(int error_code) __attribute__ ((noreturn));
long sys_getcwd(char *buf, size_t size);
long sys_chdir(const char *pathname);
long sys_rename(const char *oldname, const char *newname);
long sys_mkdir(const char *pathname, int mode);
long sys_rmdir(const char *pathname);
long sys_creat(const char *pathname, int mode);
long sys_link(const char *oldname, const char *newname);
long sys_unlink(const char *pathname);
long sys_readlink(const char *path, char *buf, size_t bufsz);
long sys_chmod(const char *filename, mode_t mode);
long sys_chown(const char *filename, uid_t user, gid_t group);
long sys_umask(int mask);
long sys_gettimeofday(struct timeval *tv, struct timezone *tz);
long sys_getuid();
long sys_getgid();
long sys_setuid(uid_t uid);
long sys_setgid(gid_t gid);
long sys_geteuid();
long sys_getegid();
long sys_rt_sigaction(int sig, const struct sigaction *act, struct sigaction *oact, size_t sigsetsize);
long sys_rt_sigprocmask(int how, sigset_t *set,	sigset_t *oset, size_t sigsetsize);
long sys_rt_sigpending(sigset_t *set, size_t sigsetsize);
long sys_alarm(unsigned int seconds);

/* wrappers */
ssize_t	read(int fd, char *buf, size_t count);
ssize_t	write(int fd, const void *buf, size_t count);
int	open(const char *filename, int flags, ... /*mode*/);
int	close(unsigned int fd);
void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off);
int	mprotect(void *addr, size_t len, int prot);
int	munmap(void *addr, size_t len);
int	pipe(int *filedes);
int	dup(int filedes);
int	dup2(int oldfd, int newfd);
int	pause();
int	nanosleep(struct timespec *rqtp, struct timespec *rmtp);
pid_t	fork(void);
void	exit(int error_code);
char *getcwd(char *buf, size_t size);
int	chdir(const char *pathname);
int	rename(const char *oldname, const char *newname);
int	mkdir(const char *pathname, int mode);
int	rmdir(const char *pathname);
int	creat(const char *pathname, int mode);
int	link(const char *oldname, const char *newname);
int	unlink(const char *pathname);
ssize_t	readlink(const char *path, char *buf, size_t bufsz);
int	chmod(const char *filename, mode_t mode);
int	chown(const char *filename, uid_t user, gid_t group);
int	umask(int mask);
int	gettimeofday(struct timeval *tv, struct timezone *tz);
uid_t	getuid();
gid_t	getgid();
int	setuid(uid_t uid);
int	setgid(gid_t gid);
uid_t	geteuid();
gid_t	getegid();

void bzero(void *s, size_t size);
size_t strlen(const char *s);
void perror(const char *prefix);
unsigned int sleep(unsigned int s);
void *memset(void *str, int c, size_t n);

void* __myrt(void);
int  setjmp(jmp_buf env);
void longjmp(jmp_buf env, int val);

sighandler_t signal(int signum, sighandler_t handler);
int sigaction(int signum, struct sigaction *act, struct sigaction *oldact);
int sigprocmask(int how, sigset_t *set, sigset_t *oldset);
int sigpending(sigset_t *set);
unsigned int alarm(unsigned int seconds);
int sigemptyset(sigset_t *set);
int sigfillset(sigset_t *set);
int sigaddset(sigset_t *set, int signo);
int sigdelset(sigset_t *set, int signo);
int sigismember(const sigset_t *set, int signo);

#endif