/**
 *
 * Convert an ELF executable to shellcode
 *
 * This is basically elf2bin but with a shellcode loader appended
 *
 */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <arpa/inet.h>

#include "elf.h"

// Copy/save relevant data/info needed for the binary image
#define MAP(LONG,INT,SHORT) \
	for(ii = 0; ii < SHORT(ehdr->e_phnum); ii++, phdr++) { \
		if(INT(phdr->p_type) == PT_LOAD) { \
			source = data + LONG(phdr->p_offset); \
			dest = mapping + LONG(phdr->p_vaddr); \
			len = LONG(phdr->p_filesz); \
			printf("memcpy(%p, %p, %08zx)\n", dest, source, len); \
			memcpy(dest, source, len); \
			used = LONG(phdr->p_memsz) + LONG(phdr->p_vaddr); \
		} else if (INT(phdr->p_type) == PT_DYNAMIC) { \
		} \
	} \
	while (INT(shdr->sh_type) != SHT_STRTAB) shdr++;

#define NOP(T) T

#define MAP_LE MAP(NOP,NOP,NOP)
#define MAP_BE MAP(ntohl,ntohl,ntohs)
#define MAP_BE64 MAP(bswap64,ntohl,ntohs)

uint64_t bswap64(uint64_t x)
{
	return (x << 56) | (x << 40 & 0xff000000000000ULL) | (x << 24 & 0xff0000000000ULL) | (x << 8 & 0xff00000000ULL) |
		(x >> 8 & 0xff000000ULL) | (x >> 24 & 0xff0000ULL) | (x >> 40 & 0xff00ULL) | (x >> 56);
}

int main(int argc, char **argv)
{
	int fd;
	struct stat statbuf;
	unsigned char *data; // ELF file
	unsigned char *base; // base memory location
	unsigned char *mapping; // target memory location
	size_t len, used = 0;
	int ii;
	unsigned char *source, *dest;

	Elf32_Ehdr *arch;

	if(argc < 3) {
		printf("elf2bin [input file] [output file]\n");
		exit(EXIT_FAILURE);
	}

	// Load input ELF executable into memory
	fd = open(argv[1], O_RDONLY);
	if(fd == -1) {
		printf("Failed to open %s: %s\n", argv[1], strerror(errno));
		exit(EXIT_FAILURE);
	}

	if(fstat(fd, &statbuf) == -1) {
		printf("Failed to fstat(fd): %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	data = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if(data == MAP_FAILED) {
		printf("Unable to read ELF file in: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	close(fd);

	// Setup area in memory to contain the new binary image
	mapping = calloc(1, 0x1000000);
	if(mapping == MAP_FAILED) {
		printf("Failed to mmap(): %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	printf("data @ %p, mapping @ %p\n", data, mapping);

	// Locate ELF program and section headers, and also the symbol table
	arch = (Elf32_Ehdr *)data;

	base = mapping;
	mapping += 0x1000;

	if (arch->e_machine == EM_ARM) {
		char entryjump[0x1000] = {
			0x08, 0x10, 0x4f, 0xe2, 0x01, 0x1a, 0x81, 0xe2, 0x0f, 0xd0, 0xcd, 0xe3,
			0x28, 0xd0, 0x8d, 0xe2, 0x6d, 0x40, 0xa0, 0xe3, 0x04, 0x40, 0x2d, 0xe5,
			0x02, 0x40, 0xa0, 0xe3, 0x0d, 0x50, 0xa0, 0xe1, 0x0c, 0x60, 0xa0, 0xe1,
			0x00, 0x70, 0xa0, 0xe3, 0x00, 0x80, 0xa0, 0xe3, 0x07, 0x90, 0xa0, 0xe3,
			0x01, 0xa0, 0xa0, 0xe1, 0x00, 0xb0, 0xa0, 0xe3, 0x00, 0xc0, 0xa0, 0xe3,
			0xf0, 0x1f, 0x2d, 0xe9, 0x04, 0x00, 0x9f, 0xe5, 0x01, 0x00, 0x80, 0xe0,
			0x10, 0xff, 0x2f, 0xe1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		};

		*(long*)(entryjump + 0x4c) = (long)arch->e_entry;
		memcpy(base, entryjump, sizeof(entryjump));
	} else if (arch->e_machine == EM_AARCH64) {
		char entryjump[0x1000] = {
			0x0a, 0x00, 0x00, 0x10, 0x4a, 0x05, 0x40, 0x91, 0xc0, 0x03, 0x00, 0x10,
			0x00, 0x00, 0x40, 0xf9, 0x00, 0x00, 0x0a, 0x8b, 0xee, 0x03, 0x00, 0xaa,
			0xe0, 0x03, 0x00, 0x91, 0x1f, 0xec, 0x7c, 0x92, 0xff, 0x83, 0x01, 0x91,
			0x40, 0x00, 0x80, 0xd2, 0xa1, 0x0d, 0x80, 0xd2, 0xe1, 0x03, 0x00, 0xf9,
			0xe1, 0x03, 0x00, 0x91, 0xe2, 0x03, 0x0c, 0xaa, 0x03, 0x00, 0x80, 0xd2,
			0x04, 0x00, 0x80, 0xd2, 0xe5, 0x00, 0x80, 0xd2, 0xe6, 0x03, 0x0a, 0xaa,
			0xc7, 0x00, 0x80, 0xd2, 0x08, 0x00, 0x82, 0xd2, 0x29, 0x03, 0x80, 0xd2,
			0xea, 0x03, 0x0a, 0xaa, 0x0b, 0x00, 0x80, 0xd2, 0xea, 0x2f, 0xbf, 0xa9,
			0xe8, 0x27, 0xbf, 0xa9, 0xe6, 0x1f, 0xbf, 0xa9, 0xe4, 0x17, 0xbf, 0xa9,
			0xe2, 0x0f, 0xbf, 0xa9, 0xe0, 0x07, 0xbf, 0xa9, 0x1d, 0x00, 0x80, 0xd2,
			0x1e, 0x00, 0x80, 0xd2, 0xc0, 0x01, 0x1f, 0xd6, 0x41, 0x00, 0x00, 0x00,
			0x41, 0x00, 0x00, 0x00
		};

		*(long*)(entryjump + 0x80) = (long)arch->e_entry;
		memcpy(base, entryjump, sizeof(entryjump));
	} else {
		char entryjump[0x1000] = {
			0x48, 0x8d, 0x05, 0xf9, 0xff, 0xff, 0xff, 0x48, 0x05, 0x00, 0x10, 0x00,
			0x00, 0x48, 0x89, 0xc6, 0x48, 0x83, 0xe4, 0xf0, 0x66, 0x83, 0xc4, 0x50,
			0x48, 0xc7, 0xc0, 0x6d, 0x00, 0x00, 0x00, 0x50, 0x48, 0x89, 0xe1, 0x48,
			0x31, 0xdb, 0x53, 0x53, 0x56, 0x48, 0xc7, 0xc0, 0x07, 0x00, 0x00, 0x00,
			0x50, 0x53, 0x53, 0x57, 0x51, 0x48, 0xc7, 0xc0, 0x02, 0x00, 0x00, 0x00,
			0x50, 0x48, 0xb8, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x48,
			0x01, 0xc6, 0xff, 0xe6, 0x0a,
		};

		*(long*)(entryjump + 0x3f) = (long)arch->e_entry;
		memcpy(base, entryjump, sizeof(entryjump));
	}

	if (arch->e_ident[EI_CLASS] == ELFCLASS32) {
		Elf32_Ehdr *ehdr = (Elf32_Ehdr *)data;
		Elf32_Phdr *phdr = (Elf32_Phdr *)(data + ehdr->e_phoff);
		Elf32_Shdr *shdr = (Elf32_Shdr *)(data + ehdr->e_shoff);
		Elf32_Sym  *symb, *symb_end;

		if (arch->e_ident[EI_DATA] == ELFDATA2LSB) {
			while (shdr->sh_type != SHT_SYMTAB) shdr++;
			symb = (Elf32_Sym *)(data + shdr->sh_offset);
			symb_end = (Elf32_Sym *)((void *)symb + shdr->sh_size);
			MAP_LE
		} else {
			phdr = (Elf32_Phdr *)(data + ntohl(ehdr->e_phoff));
			shdr = (Elf32_Shdr *)(data + ntohl(ehdr->e_shoff));
			while (ntohl(shdr->sh_type) != SHT_SYMTAB) shdr++;
			symb = (Elf32_Sym *)(data + ntohl(shdr->sh_offset));
			symb_end = (Elf32_Sym *)((void *)symb + ntohl(shdr->sh_size));
			MAP_BE
		}
	} else {
		Elf64_Ehdr *ehdr = (Elf64_Ehdr *)data;
		Elf64_Phdr *phdr = (Elf64_Phdr *)(data + ehdr->e_phoff);
		Elf64_Shdr *shdr = (Elf64_Shdr *)(data + ehdr->e_shoff);
		Elf64_Sym  *symb, *symb_end;

		if (arch->e_ident[EI_DATA] == ELFDATA2LSB) {
			while (shdr->sh_type != SHT_SYMTAB) shdr++;
			symb = (Elf64_Sym *)(data + shdr->sh_offset);
			symb_end = (Elf64_Sym *)((void *)symb + shdr->sh_size);
			MAP_LE
		} else {
			phdr = (Elf64_Phdr *)(data + bswap64(ehdr->e_phoff));
			shdr = (Elf64_Shdr *)(data + bswap64(ehdr->e_shoff));
			while (ntohl(shdr->sh_type) != SHT_SYMTAB) shdr++;
			symb = (Elf64_Sym *)(data + bswap64(shdr->sh_offset));
			symb_end = (Elf64_Sym *)((void *)symb + bswap64(shdr->sh_size));
			MAP_BE64
		}
	}


	fd = open(argv[2], O_RDWR|O_TRUNC|O_CREAT, 0644);
	if(fd == -1) {
		printf("Unable to dump memory: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	used += 0x1000;
	if(write(fd, base, used) != used) {
		printf("Unable to complete memory dump\n");
		exit(EXIT_FAILURE);
	}

	close(fd);

	return 0;
}
