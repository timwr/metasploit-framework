#include <stdio.h>
#include <string.h>

#include <dlfcn.h>

#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld.h>

#include <sys/types.h>


#if __LP64__
	#define LC_SEGMENT_COMMAND			LC_SEGMENT_64
	#define LC_ROUTINES_COMMAND			LC_ROUTINES_64
	typedef struct mach_header_64		macho_header;
	typedef struct section_64			macho_section;
	typedef struct nlist_64				macho_nlist;
	typedef struct segment_command_64	macho_segment_command;
#else
	#define LC_SEGMENT_COMMAND		LC_SEGMENT
	#define LC_ROUTINES_COMMAND		LC_ROUTINES
	typedef struct mach_header		macho_header;
	typedef struct section			macho_section;
	typedef struct nlist			macho_nlist;
	typedef struct segment_command	macho_segment_command;
#endif

extern const macho_header __dso_handle;


#ifdef __LP64__
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif

#ifndef SEG_DATA_CONST
#define SEG_DATA_CONST  "__DATA_CONST"
#endif
typedef NSObjectFileImageReturnCode (*NSCreateObjectFileImageFromMemory_ptr)(void *address, unsigned long size, NSObjectFileImage *objectFileImage);
typedef NSModule (*NSLinkModule_ptr)(NSObjectFileImage objectFileImage, const char* moduleName, unsigned long options);
typedef void (*_dyld_register_func_for_add_image_ptr)(void (*func)(struct mach_header* mh, unsigned long vmaddr_slide));
typedef int (*fprintf_ptr)( FILE * stream, const char * format, ... );
typedef void* (*dlsym_ptr)(void *handle, const char *symbol);

void* stderr_ptr = 0;
fprintf_ptr fprintf_func = 0;
dlsym_ptr dlsym_func = 0;

// This function may be overriden by application code
// to do custom error handling when a lazy symbol cannot be  
// resolved.
int dyld_lazy_dylib_proxy() __attribute__((weak,visibility("hidden")));
int dyld_lazy_dylib_proxy()
{
	return 0;
}


// This function may be overriden by application code
// to dynamically change the path to a loaded lazy dylib. 
const char* dyld_lazy_dylib_path_fix(const char*) __attribute__((weak,visibility("hidden")));
const char* dyld_lazy_dylib_path_fix(const char* path)
{
	return path;
}


static void* getHandleForLazyOrdinal(const macho_header* mh, void* handles[], uint8_t ordinal)
{
	const uint32_t cmd_count = mh->ncmds;
	const struct load_command* const cmds = (struct load_command*)((char*)mh + sizeof(macho_header));
	const struct load_command* cmd = cmds;
	uint8_t loadDylibCount = 0;
	uint8_t loadLazyDylibCount = 0;
	uint32_t i;
	// walk load commands to find LC_LAZY_LOAD_DYLIB that matches ordinal
	for (i = 0; i < cmd_count; ++i) {
		switch ( cmd->cmd ) {
			case LC_LOAD_DYLIB:
			case LC_LOAD_WEAK_DYLIB:
			case LC_LOAD_UPWARD_DYLIB:
				++loadDylibCount;
				break;
			case LC_LAZY_LOAD_DYLIB:
				++loadDylibCount;
				if ( loadDylibCount == ordinal ) {
					if ( handles[loadLazyDylibCount] == NULL ) {
						const struct dylib_command* dylib = (struct dylib_command*)cmd;
						const char* path = (char*)cmd + dylib->dylib.name.offset;
						const char* fixedPath = dyld_lazy_dylib_path_fix(path);
						handles[loadLazyDylibCount] = dlopen(fixedPath, RTLD_LAZY);
					}
					return handles[loadLazyDylibCount];
				}
				++loadLazyDylibCount;
				break;
		}
		cmd = (const struct load_command*)(((char*)cmd)+cmd->cmdsize);
	}
	return NULL;
}



// called by dyld_lazy_dylib_stub_binding_helper
// this function must figure out which function
// lazyPointer is supposed to point to 
// and update it it.
void* lazy_load_dylib(uintptr_t* lazyPointer)
{
	static const macho_header*	mh = NULL;
	static const macho_nlist*	symbolTable = NULL;
	static const char*			stringTable = NULL;
	static const uint8_t*		linkEditBase = NULL;
	static const uint32_t*		indirectSymbolTable = NULL;
	static intptr_t				slide = 0;
	static void*				handles[256];
	
	// do this work only on first call
	uint32_t i;
	if ( mh == NULL ) {
		const macho_header* tmh = &__dso_handle;
		fprintf_func(stderr_ptr, "%s %p\n", "go", tmh);
		// symbol table, indirect symbol table
		const uint32_t cmd_count = tmh->ncmds;
		const struct load_command* const cmds = (struct load_command*)((char*)tmh + sizeof(macho_header));
		const struct load_command* cmd = cmds;
		// first pass at load commands gets linkEditBase
		for (i = 0; i < cmd_count; ++i) {
			if ( cmd->cmd == LC_SEGMENT_COMMAND ) {
				const macho_segment_command* seg = (macho_segment_command*)cmd;
				if ( strcmp(seg->segname,"__TEXT") == 0 ) 
					slide = (uintptr_t)tmh - seg->vmaddr;
				else if ( strcmp(seg->segname,"__LINKEDIT") == 0 ) 
					linkEditBase = (uint8_t*)(seg->vmaddr + slide - seg->fileoff);
			}
			cmd = (const struct load_command*)(((char*)cmd)+cmd->cmdsize);
		}
		// next pass at load commands gets symbolTable, stringTable
		uint32_t lazyDylibCount = 0;
		cmd = cmds;
		for (i = 0; i < cmd_count; ++i) {
			switch ( cmd->cmd ) {
				case LC_SYMTAB:
					{
						const struct symtab_command* symtab = (struct symtab_command*)cmd;
						stringTable = (const char*)&linkEditBase[symtab->stroff];
						symbolTable = (macho_nlist*)(&linkEditBase[symtab->symoff]);
					}
					break;
				case LC_DYSYMTAB:
					{
						const struct dysymtab_command* dsymtab = (struct dysymtab_command*)cmd;
						indirectSymbolTable = (uint32_t*)(&linkEditBase[dsymtab->indirectsymoff]);
					}
					break;
				case LC_LAZY_LOAD_DYLIB:
					++lazyDylibCount;
					break;
			}
			cmd = (const struct load_command*)(((char*)cmd)+cmd->cmdsize);
		}
		
		// save to static global to make this thread safe
		mh = tmh;
	}
	
							/*fprintf_func(stderr_ptr, "lol %p\n", 0);*/
	return 0;
	// find lazy dylib pointer section
	/*void* result = &dyld_lazy_dylib_proxy;*/
	const uint32_t cmd_count = mh->ncmds;
	const struct load_command* const cmds = (struct load_command*)((char*)mh + sizeof(macho_header));
	const struct load_command* cmd = cmds;
	// walk sections to find one with this lazy pointer
	for (i = 0; i < cmd_count; ++i) {
		if ( cmd->cmd == LC_SEGMENT_COMMAND ) {
			const macho_segment_command* seg = (macho_segment_command*)cmd;
			const macho_section* const sectionsStart = (macho_section*)((char*)seg + sizeof(macho_segment_command));
			const macho_section* const sectionsEnd = &sectionsStart[seg->nsects];
			const macho_section* sect;
			for (sect=sectionsStart; sect < sectionsEnd; ++sect) {
				const uint8_t type = sect->flags & SECTION_TYPE;
							fprintf_func(stderr_ptr, "lol %p %p\n", sect, type);
				/*if ( type == S_LAZY_DYLIB_SYMBOL_POINTERS ) { // S_LAZY_DYLIB_SYMBOL_POINTERS*/
        if ((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS) {
					const uint32_t pointerCount = sect->size / sizeof(uintptr_t);
					uintptr_t* const symbolPointers = (uintptr_t*)(sect->addr + slide);
					if (1 || (lazyPointer >= symbolPointers) && (lazyPointer < &symbolPointers[pointerCount]) ) {
						const uint32_t indirectTableOffset = sect->reserved1;
						const uint32_t lazyIndex = lazyPointer - symbolPointers;
						uint32_t symbolIndex = indirectSymbolTable[indirectTableOffset + lazyIndex];
							const char* symbolName = &stringTable[symbolTable[symbolIndex].n_un.n_strx];
							fprintf_func(stderr_ptr, "lol %p %s\n", 1, symbolName);
						if ( symbolIndex != INDIRECT_SYMBOL_ABS && symbolIndex != INDIRECT_SYMBOL_LOCAL ) {
							// found symbol for this lazy pointer, now lookup address
							uint8_t ordinal = GET_LIBRARY_ORDINAL(symbolTable[symbolIndex].n_desc);
							void* handle = getHandleForLazyOrdinal(mh, handles, ordinal);
							if ( handle != NULL ) {
								void* addr = dlsym(handle, &symbolName[1]);
								/*if ( addr != NULL )*/
									/*result = addr;*/
								/**lazyPointer = (uintptr_t)result;*/
								/*return result;*/
							}
						}
					}
				}
			}
		}
		cmd = (const struct load_command*)(((char*)cmd)+cmd->cmdsize);
	}	
	/**lazyPointer = (uintptr_t)result;*/
	/*return result;*/
}


void parse_image(const mach_header_t *header, intptr_t slide);
/*uint64_t find_macho(uint64_t addr, unsigned int increment, unsigned int dereference);*/
uint64_t find_magic(uint64_t addr, uint32_t magic, unsigned int increment, unsigned int pointer);
uint64_t find_symbol(uint64_t base, char* symbol);
uint64_t set_symbols(uint64_t base);
uint64_t find_entry_offset(struct mach_header_64 *mh);
int string_compare(const char* s1, const char* s2);

void rebind_symbols_for_image(const mach_header_t *header, intptr_t slide);

#define DEBUG
#ifdef DEBUG
static void print(char * str);
#endif

int main(int argc, char** argv)
{
#ifdef DEBUG
	print("main!\n");
	/*fprintf(stderr, "done it:\n");*/
#endif
	uint64_t buffer = 0;
	uint64_t buffer_size = 0;
#ifdef __x86_64
	__asm__(
			"movq %%r10, %0;\n"
			"movq %%r12, %1;\n"
			: "=g"(buffer), "=g"(buffer_size));
	if (buffer == -1) {
		return 0;
	}
	if (buffer_size == -1) {
		return 0;
	}
#else
	/*if (!buffer) {*/
		/*return 0;*/
	/*}*/
#endif

#ifdef DEBUG
	print("hello world!\n");
#endif

	uint64_t binary = find_magic(0x100000000, MH_MAGIC_64, 0x1000, 0);
	if (!binary) {
		return 1;
	}
	uint64_t dyld = find_magic(binary + 0x1000, MH_MAGIC_64, 0x1000, 0);
	if (!dyld) {
		return 1;
	}

#ifdef DEBUG
	print("got dyld!\n");

	stderr_ptr = (void*)find_symbol(dyld, "___stderrp");
	fprintf_func = (void*)find_symbol(dyld, "_fprintf");
	if (fprintf_func) {
		fprintf_func(stderr_ptr, "%s %p\n", "fprintf_func", fprintf_func);
		fprintf_func(stderr_ptr, "%s %p\n", "main", main);
		fprintf_func(stderr_ptr, "%s %p\n", "fprintf", fprintf);
		/*fprintf_func(stderr_ptr, "%s %p\n", "_fprintf", dlsym_func(RTLD_DEFAULT, "_fprintf"));*/
	}
	dlsym_func = (void*)find_symbol(dyld, "_dlsym");
	fprintf_func(stderr_ptr, "%s %p\n", "dlsym", dlsym_func);
	fprintf_func(stderr_ptr, "%s %p\n", "dlsym", dlsym_func(RTLD_DEFAULT, "dlsym"));

	/*set_symbols(my_macho);*/
	/*set_symbols(my_macho);*/

	lazy_load_dylib(fprintf);
	print("main!\n");

	fprintf_func(stderr_ptr, "%s %p\n", "fprintf", fprintf);
	/*rebind_symbols_for_image(my_macho, 0);*/
	_dyld_register_func_for_add_image_ptr _dyld_register_func_for_add_image_func = (void*)find_symbol(dyld, "__dyld_register_func_for_add_image");
	if (_dyld_register_func_for_add_image_func) {
		print("register add image!\n");
		_dyld_register_func_for_add_image_func(rebind_symbols_for_image);
		print("done add image!\n");
	}

	while (1) {
		sleep(100);
	}

	uint64_t my_macho = find_magic(0x100000000, 0xfeedfa63, 0x1000, 0);
	if (!my_macho) {
		return 1;
	}
	fprintf_func(stderr_ptr, "%s %p\n", "my_macho", my_macho);
	/*set_symbols(my_macho);*/
	/*fix_bindings(my_macho);*/
	fprintf_func(stderr_ptr, "%s %p\n", "done", my_macho);
	/*set_symbols(buffer);*/
	fprintf_func(stderr_ptr, "%s %p\n", "buffer", my_macho);

#endif
#ifdef __x86_64
	NSCreateObjectFileImageFromMemory_ptr NSCreateObjectFileImageFromMemory_func = (void*)find_symbol(dyld, "_NSCreateObjectFileImageFromMemory");
	if (!NSCreateObjectFileImageFromMemory_func) {
		return 1;
	} 

	NSLinkModule_ptr NSLinkModule_func = (void*)find_symbol(dyld, "_NSLinkModule");
	if (!NSLinkModule_func) {
		return 1;
	} 
#else
#ifdef DEBUG
	print("good symbol!\n");
#endif
	NSCreateObjectFileImageFromMemory_ptr NSCreateObjectFileImageFromMemory_func = 0;
	NSLinkModule_ptr NSLinkModule_func = 0;

	/*if (dlsym_func)*/
	/*print("great symbol!\n");*/

	return 0;
#endif

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
	execute_base = find_magic(execute_base, MH_MAGIC_64, sizeof(int), 1);

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

static void fix_bindings( section_t *section, intptr_t slide, nlist_t *symtab, char *strtab, uint32_t *indirect_symtab) 
{
	fprintf_func(stderr_ptr, "fix_bindings %p %p\n", section, indirect_symtab);
  uint32_t *indirect_symbol_indices = indirect_symtab + section->reserved1;
  void **indirect_symbol_bindings = (void **)((uintptr_t)slide + section->addr);
	fprintf_func(stderr_ptr, "indirect_bindings %p %p\n", indirect_symbol_indices, indirect_symbol_bindings);
  for (uint i = 0; i < section->size / sizeof(void *); i++) {
    uint32_t symtab_index = indirect_symbol_indices[i];
    if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
        symtab_index == (INDIRECT_SYMBOL_LOCAL   | INDIRECT_SYMBOL_ABS)) {
      continue;
    }
    uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
    char *symbol_name = strtab + strtab_offset;
		if (string_compare(symbol_name, "_fprintf") == 0) {
			fprintf_func(stderr_ptr, "fprintf %p %p %p\n", fprintf, indirect_symbol_bindings[i],  fprintf_func);
		}
		fprintf_func(stderr_ptr, "symbol %s %p %p\n", symbol_name, indirect_symbol_bindings[i],  i);
		if (0 && indirect_symbol_bindings[i] == fprintf) {
			fprintf(stderr, "testing");
			fprintf_func(stderr_ptr, "fprintf %p %p %p\n", fprintf, indirect_symbol_bindings[i],  fprintf_func);
			indirect_symbol_bindings[i] = fprintf_func;
			fprintf(stderr, "tested");
			fprintf_func(stderr_ptr, "fprintf %p %p %p\n", fprintf, indirect_symbol_bindings[i],  fprintf_func);
			/*fprintf(stderr, "%s %p\n", symbol_name, indirect_symbol_bindings[i]);*/
			/*print("!!!!\n");*/
			/*print(symbol_name);*/
			/*print("!!!!\n");*/
		}
	}
}

void parse_image(const mach_header_t *header, intptr_t slide) 
{
	fprintf_func(stderr_ptr, "parse_image %p %p\n", header, slide);
  /*Dl_info info;*/
  /*if (dladdr(header, &info) == 0) {*/
    /*return;*/
  /*}*/

  segment_command_t *cur_seg_cmd;
  segment_command_t *linkedit_segment = NULL;
  struct symtab_command* symtab_cmd = NULL;
  struct dysymtab_command* dysymtab_cmd = NULL;

  uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
  for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
    cur_seg_cmd = (segment_command_t *)cur;
		/*fprintf_func(stderr_ptr, "segmend %p %p %p\n", cur_seg_cmd, cur_seg_cmd->cmd, cur_seg_cmd->cmdsize);*/
    if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      if (string_compare(cur_seg_cmd->segname, SEG_LINKEDIT) == 0) {
        linkedit_segment = cur_seg_cmd;
      }
    } else if (cur_seg_cmd->cmd == LC_SYMTAB) {
      symtab_cmd = (struct symtab_command*)cur_seg_cmd;
    } else if (cur_seg_cmd->cmd == LC_DYSYMTAB) {
      dysymtab_cmd = (struct dysymtab_command*)cur_seg_cmd;
    }
		/*fprintf_func(stderr_ptr, "segmend %p %s\n", cur_seg_cmd, cur_seg_cmd->segname);*/
  }

  if (!symtab_cmd || !dysymtab_cmd || !linkedit_segment ||
      !dysymtab_cmd->nindirectsyms) {
    return;
  }

	/*unsigned long file_slide = linkedit->vmaddr - text->vmaddr - linkedit->fileoff;*/
	/*strtab = (char *)(base + file_slide + symtab->stroff);*/
	/*nl = (struct nlist_64 *)(base + file_slide + symtab->symoff);*/

  // Find base symbol/string table addresses
  uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
  nlist_t *symtab = (nlist_t *)(linkedit_base + symtab_cmd->symoff);
  char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);

	/*print(strtab);*/

  // Get indirect symbol table (array of uint32_t indices into symbol table)
  uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);
	fprintf_func(stderr_ptr, "syms %p %p %p\n", linkedit_base, linkedit_segment, indirect_symtab);

  cur = (uintptr_t)header + sizeof(mach_header_t);
  for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
    cur_seg_cmd = (segment_command_t *)cur;
    if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      if (string_compare(cur_seg_cmd->segname, SEG_DATA) != 0 &&
          string_compare(cur_seg_cmd->segname, SEG_DATA_CONST) != 0) {
        continue;
			}
			fprintf_func(stderr_ptr, "rebind %p %s\n", cur_seg_cmd, cur_seg_cmd->segname);
			for (uint j = 0; j < cur_seg_cmd->nsects; j++) {
        section_t *sect = (section_t *)(cur + sizeof(segment_command_t)) + j;
        if ((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS) {
					fprintf_func(stderr_ptr, "section %p %s %s\n", sect, sect->segname, sect->sectname);
					/*print("lolol");*/
					fix_bindings(sect, slide, symtab, strtab, indirect_symtab);
        }
        if ((sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
					fprintf_func(stderr_ptr, "section %p %s %s\n", sect, sect->segname, sect->sectname);
					fix_bindings(sect, slide, symtab, strtab, indirect_symtab);
					/*print("lolal");*/
          /*perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab);*/
        }
      }
    }
  }
}

uint64_t set_symbols(uint64_t base);
void rebind_symbols_for_image(const mach_header_t *header, intptr_t slide)
{
		if ((uint64_t)header > 0x7fff00000000) {
		/*fprintf_func(stderr_ptr, "skip %p %p\n", header, slide);*/
		/*} else {*/
		fprintf_func(stderr_ptr, "rebind %p %p\n", header, slide);
		/*set_symbols(header);*/
		/*parse_image(header, slide);*/
		}
}

uint64_t set_symbols(uint64_t base) 
{
	fprintf_func(stderr_ptr, "set_symbols %p %p\n", base, *(uint32_t*)base);
	/*return 0;*/
	struct segment_command_64 *sc, *linkedit, *text;
	struct load_command *lc;
	struct symtab_command *symtab;
	struct dysymtab_command *dysymtab;
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
		} else if (lc->cmd == LC_DYSYMTAB) {
			dysymtab = (struct dysymtab_command*)lc;
		}
		lc = (struct load_command *)((unsigned long)lc + lc->cmdsize);
	}

	if (!linkedit || !symtab || !text || !dysymtab) return 0;

	uint32_t *indirect_symtab = (uint32_t *)((linkedit - linkedit->fileoff) + dysymtab->indirectsymoff);
	fprintf_func(stderr_ptr, "symtab %p %p %p %p\n", text, linkedit, symtab, dysymtab);
	/*fprintf_func(stderr_ptr, "symtab %p %p %p %p\n", (text - base), (linkedit - base), (symtab - base), (dysymtab - base));*/

	unsigned long file_slide = linkedit->vmaddr - text->vmaddr - linkedit->fileoff;
	fprintf_func(stderr_ptr, "file_slide %p %p %p %p\n", file_slide, linkedit->vmaddr, text->vmaddr, linkedit->fileoff);
	fprintf_func(stderr_ptr, "symtab %p %p %p %p\n", dysymtab, dysymtab->indirectsymoff, dysymtab->nindirectsyms, indirect_symtab);
	strtab = (char *)(base + file_slide + symtab->stroff);
	fprintf_func(stderr_ptr, ">>>>>>>>>>>> %p %p %p %p\n", file_slide, strtab, (base + symtab->stroff));
	/*fprintf_func(stderr_ptr, "symtab %p %p %p %p\n", dysymtab, dysymtab->indirectsymoff, dysymtab->nindirectsyms, *indirect_symtab);*/
	return 0;

	nl = (struct nlist_64 *)(base + file_slide + symtab->symoff);
	for (int i=0; i<symtab->nsyms; i++) {
		char *name = strtab + nl[i].n_un.n_strx;
		#ifdef DEBUG
		fprintf_func(stderr_ptr, "nl symbol %p %s %p %p %p\n", i, name, (base + nl[i].n_value), nl[i].n_sect, nl[i].n_value);
		#endif
		/*symbol = base + */
		if (nl[i].n_value == 0) {
			void* symbol = dlsym_func(RTLD_DEFAULT, name + 1);
			if (symbol) {
				/*fprintf_func(stderr_ptr, "linking %s %p %p -> %p\n", name, symbol, nl[i].n_value, (symbol - base));*/
				/*nl[i].n_sect = 0x1;*/
				/*nl[i].n_value = symbol - base;*/
			}
		}

		/*if (string_compare(name, symbol) == 0) {*/
			/*return base + nl[i].n_value;*/
		/*}*/
	}

	fprintf_func(stderr_ptr, "base %p %p %p\n", (void*)base + 0x3000, (base + 0x3000), *(uint64_t*)(base + 0x3000));
	return 0;
	/*fprintf(stderr_ptr, "lol\n");*/

	nl = (struct nlist_64 *)(base + file_slide + symtab->symoff);
	for (int i=0; i<symtab->nsyms; i++) {
		char *name = strtab + nl[i].n_un.n_strx;
		#ifdef DEBUG
		fprintf_func(stderr_ptr, "symbol %p %s %p\n", (base + nl[i].n_value), name, nl[i].n_value);
		#endif
		/*symbol = base + */
		if (nl[i].n_value == 0) {
			void* symbol = dlsym_func(RTLD_DEFAULT, name + 1);
			/*if (symbol) {*/
				/*fprintf_func(stderr_ptr, "linking %s %p %p -> %p\n", name, symbol, nl[i].n_value, (symbol - base));*/
				/*nl[i].n_value = symbol - base;*/
			/*}*/
		}

		/*if (string_compare(name, symbol) == 0) {*/
			/*return base + nl[i].n_value;*/
		/*}*/
	}
	/*fprintf(stderr_ptr, "lol\n");*/
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

	if (!linkedit || !symtab || !text) return 0;

	unsigned long file_slide = linkedit->vmaddr - text->vmaddr - linkedit->fileoff;
	strtab = (char *)(base + file_slide + symtab->stroff);

	nl = (struct nlist_64 *)(base + file_slide + symtab->symoff);
	for (int i=0; i<symtab->nsyms; i++) {
		char *name = strtab + nl[i].n_un.n_strx;
		#ifdef DEBUG
		/*print(name);*/
		/*print("\n");*/
		/*if (fprintf_func && stderr_ptr)*/
			/*fprintf_func(stderr_ptr, "symbol %p %s %p\n", (base + nl[i].n_value), name, nl[i].n_value);*/
		#endif

		if (string_compare(name, symbol) == 0) {
			return base + nl[i].n_value;
		}
	}

	return 0;
}

uint64_t syscall_chmod(uint64_t path, long mode) 
{
	uint64_t ret = 0;
#ifdef __x86_64
	uint64_t chmod_no = 0x200000f;
	__asm__(
			"movq %1, %%rax;\n"
			"movq %2, %%rdi;\n"
			"movq %3, %%rsi;\n"
			"syscall;\n"
			"movq %%rax, %0;\n"
			: "=g"(ret)
			: "g"(chmod_no), "S"(path), "g"(mode)
			:);
#else
	uint64_t chmod_no = 0xf;
	asm volatile(
			"mov x0, %2;\n"
			"mov x1, %3;\n"
			"mov x16, %1;\n"
			"svc 0x80;\n"
			"mov %0, x0;\n"
			: "=r"(ret)
			: "r"(chmod_no), "r"(path), "r"(mode)
			: "x0", "x1", "x16");
#endif
	return ret;
}

uint64_t find_magic(uint64_t addr, uint32_t magic, unsigned int increment, unsigned int pointer) 
{
	while(1) {
		uint64_t ptr = addr;
		if (pointer) {
			ptr = *(uint64_t *)ptr;
		}
		unsigned long ret = syscall_chmod(ptr, 0777);
		if (ret == 0x2 && ((int *)ptr)[0] == magic) {
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
	long stdout = 1;
	unsigned long len = string_len(str);
	unsigned long long addr = (unsigned long long) str;
	unsigned long ret = 0;

	/* ret = write(stdout, str, len); */
#ifdef __x86_64
	long write = 0x2000004;
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
#else
	uint64_t write = 0x04;
	register uint64_t x16 asm("x16") = write;
	register uint64_t x0 asm("x0") = stdout;
	register uint64_t x1 asm("x1") = addr;
	register uint64_t x2 asm("x2") = len;
	register uint64_t xret asm("x0");
	asm volatile(
			"mov x0, %2;\n"
			"mov x1, %3;\n"
			"mov x2, %4;\n"
			"mov x16, %1;\n"
			"svc 0x80;\n"
			"mov %0, x0;\n"
			: "=r"(xret)
			: "r"(x16), "r"(x0), "r"(addr), "r"(len)
			:);
	ret = xret;
#endif

}
#endif
