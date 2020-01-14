#include <stdio.h>
#include <elf.h>
#include <stdlib.h>
#include <string.h>

char *parseShType(Elf64_Word type) {
	if (type == SHT_NULL)
		return "SHT_NULL";
	else if (type == SHT_PROGBITS)
		return "SHT_PROGBITS";
	else if (type == SHT_SYMTAB)
		return "SHT_SYMTAB";
	else if (type == SHT_STRTAB)
		return "SHT_STRTAB";
	else if (type == SHT_RELA)
		return "SHT_RELA";
	else if (type == SHT_HASH)
		return "SHT_HASH";
	else if (type == SHT_DYNAMIC)
		return "SHT_DYNAMIC";
	else if (type == SHT_NOTE)
		return "SHT_NOTE";
	else if (type == SHT_NOBITS)
		return "SHT_NOBITS";
	else if (type == SHT_REL)
		return "SHT_REL";
	else if (type == SHT_SHLIB)
		return "SHT_SHLIB";
	else if (type == SHT_DYNSYM)
		return "SHT_DYNSYM";
	else if (type == SHT_LOUSER)
		return "SHT_LOUSER";
	else if (type == SHT_HIUSER)
		return "SHT_HIUSER";
	else
		return "UNKNOWN";
}

void printSymTbl() {

}
int main(int argc, char **argv)
{

	if (argc < 2) {
		printf("[!] Usage: %s <ELF>\n",argv[0]);
		return 0;
	}
	Elf64_Ehdr header;

	FILE* file = fopen(argv[1], "rb");
	if (file) {
		fread(&header, 1, sizeof(header), file);
		/*
		 * ELFMAG = ELF signature
		 * SELFMAG = Length of ELF signature
		 */
		if (memcmp(header.e_ident, ELFMAG, SELFMAG) == 0) {
			printf("[+] ELF Signature\n");
			printf(" -> 0x%02x\n",*header.e_ident);
			printf(" -> 0x%02x\n",*(header.e_ident+1));
			printf(" -> 0x%02x\n",*(header.e_ident+2));
			printf(" -> 0x%02x\n",*(header.e_ident+3));
		} else {
			printf("[!] Not an ELF file!\n");
			return 0;
		}
		
		printf("[+] File Architecture\n");
		printf(" -> 0x%02x\n",*(header.e_ident+4));

		printf("[+] Endian\n");
		printf(" -> 0x%02x\n",*(header.e_ident+5));

		printf("[+] ELF Version\n");
		printf(" -> 0x%02x\n",*(header.e_ident+6));

		printf("[+] OS ABI\n");
		printf(" -> 0x%02x\n",*(header.e_ident+7));

		printf("[+] ABI Version\n");
		printf(" -> 0x%02x\n",*(header.e_ident+8));

		printf("[+] E_TYPE\n");
		printf(" -> 0x%04x\n",header.e_type);

		printf("[+] E_MACHINE\n");
		printf(" -> 0x%04x\n",header.e_machine);

		printf("[+] E_VERSION\n");
		printf(" -> 0x%04x\n",header.e_version);

		printf("[+] E_ENTRY\n");
		printf(" -> 0x%016x\n",header.e_entry);

		printf("[+] E_PHOFF\n");
		printf(" -> 0x%016x\n",header.e_phoff);

		printf("[+] E_SHOFF\n");
		printf(" -> 0x%016x\n",header.e_shoff);

		printf("[+] E_FLAGS\n");
		printf(" -> 0x%04x\n",header.e_flags);

		printf("[+] E_EHSIZE\n");
		printf(" -> 0x%02x\n",header.e_ehsize);

		printf("[+] E_PHENTSIZE\n");
		printf(" -> 0x%02x\n",header.e_phentsize);

		printf("[+] E_PHNUM\n");
		printf(" -> 0x%02x\n",header.e_phnum);

		printf("[+] E_SHENTSIZE\n");
		printf(" -> 0x%02x\n",header.e_shentsize);

		printf("[+] E_SHNUM\n");
		printf(" -> 0x%02x\n",header.e_shnum);

		printf("[+] E_SHSTRNDX\n");
		printf(" -> 0x%02x\n",header.e_shstrndx);
		
		fclose(file);

		printf("\n[============================]\n");
		printf("[+] Program Headers\n");
		printf("[============================]\n");
		
		/*
		 * Get Program Header
		 * Create pointer to Elf64 header struct
		 * header start + program header offset member = first PH
		 */

		file = fopen(argv[1],"rb");
		if (file) {
			
			fseek(file,header.e_phoff,SEEK_CUR);

			Elf64_Phdr *phdr = malloc(sizeof(Elf64_Phdr)*header.e_phnum);
			memset(phdr, '\0', sizeof(Elf64_Phdr)*header.e_phnum);
			fread(phdr, header.e_phnum ,sizeof(Elf64_Phdr), file);

			for (int i = 0; i < header.e_phnum; i++) {
				printf("[+] PHeader %d\n",i);
				printf(" p_type \t-> %08x\n",phdr[i].p_type);
				printf(" p_flags \t-> %08x\n",phdr[i].p_flags);
				printf(" p_offset \t-> 0x%016x\n",phdr[i].p_offset);
				printf(" p_vaddr \t-> 0x%016x\n",phdr[i].p_vaddr);
				printf(" p_paddr \t-> 0x%016x\n",phdr[i].p_paddr);
				printf(" p_filesz \t-> 0x%016x\n",phdr[i].p_filesz);
				printf(" p_memsz \t-> 0x%016x\n",phdr[i].p_memsz);
				printf(" p_align \t-> 0x%016x\n",phdr[i].p_align);
			}
			free(phdr);
			phdr = NULL;
			fclose(file);
			
		}

		/*
		 * Section headers
		 */
		file = fopen(argv[1],"rb");
		if (file) {
			printf("\n[===========================]\n");
			printf("[+] Section Headers\n");
			printf("[===========================]\n");
			fseek(file,header.e_shoff,SEEK_CUR);

			Elf64_Shdr *shdr = malloc(sizeof(Elf64_Shdr)*header.e_shnum);
			memset(shdr, '\0', sizeof(Elf64_Shdr)*header.e_shnum);
			fread(shdr, header.e_shnum, sizeof(Elf64_Shdr),file);

			for (int i = 0; i < header.e_shnum; i++) {
				printf("[+] SHeader %d\n",i);
				printf(" sh_name \t-> 0x%08x\n",shdr[i].sh_name);
				printf(" sh_type \t-> 0x%08x \t[%s]\n",shdr[i].sh_type,parseShType(shdr[i].sh_type));
				printf(" sh_flags \t-> 0x%016x\n",shdr[i].sh_flags);
				printf(" sh_addr \t-> 0x%016x\n",shdr[i].sh_addr);
				printf(" sh_offset \t-> 0x%016x\n",shdr[i].sh_offset);
				printf(" sh_size \t-> 0x%016x\n",shdr[i].sh_size);
				printf(" sh_link \t-> 0x%08x\n",shdr[i].sh_link);
				printf(" sh_info \t-> 0x%08x\n",shdr[i].sh_info);
				printf(" sh_addralign \t-> 0x%016x\n",shdr[i].sh_addralign);
				printf(" sh_entsize \t-> 0x%016x\n",shdr[i].sh_entsize);
			}
			free(shdr);
			shdr = NULL;
			fclose(file);
		}
		
		/*
		 * Segment tables
		 * Segments are defined in the section headers
		 */

	}
	/*
	if (shdr != NULL) {
		free(shdr);
		shdr = NULL;
	}
	if (phdr != NULL) {
		free(phdr);
		phdr = NULL;
	}*/
	printf("[!] Done\n");
}
