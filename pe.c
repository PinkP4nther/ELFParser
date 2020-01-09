#include <stdio.h>
#include <elf.h>

int main()
{
	Elf64_Ehdr header;

	FILE* file = fopen("./pe", "rb");
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
		printf(" -> %016p\n",header.e_entry);

		printf("[+] E_PHOFF\n");
		printf(" -> %016p\n",header.e_phoff);

		printf("[+] E_SHOFF\n");
		printf(" -> %016p\n",header.e_shoff);

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

		printf("[==============================]");
		printf("[+] Program Headers\n\n");
		
		/*
		 * Get Program Header
		 * Create pointer to Elf64 header struct
		 * header start + program header offset member = first PH
		 */

		//Elf64_Ehdr hdr = (Elf64_Ehdr *) header;
		//Elf64_Phdr *phdr = (Elf64_Phdr *)&header;
		Elf64_Phdr *phdr;

		phdr = (Elf64_Phdr *)((char*)&header + header.e_phoff);
		printf(" - %p\n",phdr);
		printf(" - %p\n",header.e_phnum);
		for (int i = 0; i < header.e_phnum; i++) {
			printf("[+] PHeader %d @%p\n",i,phdr[i]);
			printf(" p_type -> %08x\n",phdr[i].p_type);
			printf(" p_flags -> %08x\n",phdr[i].p_flags);
			printf(" p_offset -> %016p\n",phdr[i].p_offset);
			printf(" p_vaddr -> %016p\n",phdr[i].p_vaddr);
			printf(" p_paddr -> %016p\n",phdr[i].p_paddr);
			printf(" p_filesz -> %016p\n",phdr[i].p_filesz);
			printf(" p_memsz -> %016p\n",phdr[i].p_memsz);
			printf(" p_align -> %016p\n",phdr[i].p_align);
		}

		printf("HEADER: %p\n",&header);
		printf("PHDR: %p\n",phdr);


	}
	fclose(file);
}
