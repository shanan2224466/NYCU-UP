
%macro gensys 2
	global sys_%2:function
sys_%2:
	push	r10
	mov	r10, rcx
	mov	rax, %1
	syscall
	pop	r10
	ret
%endmacro

; RDI, RSI, RDX, RCX, R8, R9

extern	errno

	section .data

	section .text

	gensys   0, read
	gensys   1, write
	gensys   2, open
	gensys   3, close
	gensys   9, mmap
	gensys  10, mprotect
	gensys  11, munmap
	gensys  22, pipe
	gensys  32, dup
	gensys  33, dup2
	gensys  34, pause
	gensys  35, nanosleep
	gensys  57, fork
	gensys  60, exit
	gensys  79, getcwd
	gensys  80, chdir
	gensys  82, rename
	gensys  83, mkdir
	gensys  84, rmdir
	gensys  85, creat
	gensys  86, link
	gensys  88, unlink
	gensys  89, readlink
	gensys  90, chmod
	gensys  92, chown
	gensys  95, umask
	gensys  96, gettimeofday
	gensys 102, getuid
	gensys 104, getgid
	gensys 105, setuid
	gensys 106, setgid
	gensys 107, geteuid
	gensys 108, getegid

	gensys 13, rt_sigaction
	gensys 14, rt_sigprocmask
	gensys 15, rt_sigreturn
	gensys 37, alarm
	gensys 127, rt_sigpending

	; https://hackmd.io/@sysprog/c-function

	global setjmp:function
setjmp:
	; no need to push and change rbp
	lea r11, [rsp + 8]
	mov [rdi], rbx
	mov [rdi + 8], r11		; rsp
	mov [rdi + 16], rbp
	mov [rdi + 24], r12
	mov [rdi + 32], r13
	mov [rdi + 40], r14
	mov [rdi + 48], r15
	mov r11, [rsp]
	mov [rdi + 56], r11		; return address
	push rdi
	push rsi
	push rdx
	push r10
	mov rdi, 0
	mov rsi, 0
	sub rsp, 8		; prepare space for oset
	mov rdx, rsp
	mov r10, 8
	mov rax, 14
	syscall
	pop r11			; oset
	pop r10
	pop rdx
	pop rsi
	pop rdi
	mov [rdi + 64], r11
	xor rax, rax
	ret

	global longjmp:function
longjmp:
	mov rbx, [rdi]
	mov rsp, [rdi + 8]
	mov rbp, [rdi + 16]
	mov r12, [rdi + 24]
	mov r13, [rdi + 32]
	mov r14, [rdi + 40]
	mov r15, [rdi + 48]
	push QWORD [rdi + 56]	; return address
	push rdi
	push rsi
	push rdx
	push r10
	mov rdi, 2			; restore the mask
	lea r9, [rdi + 64]
	mov rsi, r9			; mask pointer
	mov rdx, 0			; no need to save the old mask
	mov r10, 8
	mov rax, 14
	syscall
	pop r10
	pop rdx
	pop rsi
	pop rdi
	mov [rdi + 64], r11
	mov rax, rsi
	cmp rax, 0
	jnz val_zero
	inc rax
val_zero:
	ret

	global open:function
open:
	call	sys_open
	cmp	rax, 0
	jge	open_success	; no error :)
open_error:
	neg	rax
%ifdef NASM
	mov	rdi, [rel errno wrt ..gotpc]
%else
	mov	rdi, [rel errno wrt ..gotpcrel]
%endif
	mov	[rdi], rax	; errno = -rax
	mov	rax, -1
	jmp	open_quit
open_success:
%ifdef NASM
	mov	rdi, [rel errno wrt ..gotpc]
%else
	mov	rdi, [rel errno wrt ..gotpcrel]
%endif
	mov	QWORD [rdi], 0	; errno = 0
open_quit:
	ret

	global __myrt:function
__myrt:
	mov rax, 15
	syscall
	ret

	global sleep:function
sleep:
	sub	rsp, 32				; allocate timespec * 2
	mov	[rsp], rdi			; req.tv_sec
	mov	QWORD [rsp+8], 0	; req.tv_nsec
	mov	rdi, rsp			; rdi = req @ rsp
	lea	rsi, [rsp+16]		; rsi = rem @ rsp+16
	call	sys_nanosleep
	cmp	rax, 0
	jge	sleep_quit	; no error :)
sleep_error:
	neg	rax
	cmp	rax, 4		; rax == EINTR?
	jne	sleep_failed
sleep_interrupted:
	lea	rsi, [rsp+16]
	mov	rax, [rsi]	; return rem.tv_sec
	jmp	sleep_quit
sleep_failed:
	mov	rax, 0		; return 0 on error
sleep_quit:
	add	rsp, 32
	ret

