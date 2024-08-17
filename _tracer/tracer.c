#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <elf.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/uio.h>

#define CHECK_CHILD_STATUS(status) do { \
    if (WIFSTOPPED(status)) { \
        printf("Child stopped with signal %d\n", WSTOPSIG(status)); \
    } else if (WIFEXITED(status)) { \
        printf("Child exited with status %d\n", WEXITSTATUS(status)); \
    } \
} while(0)


typedef struct handle {
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	uint8_t *mem;
	char *symname;
	Elf64_Addr symaddr;
	struct user_regs_struct regs;
	char *exec;
} handle_t;

Elf64_Addr lookup_symbol(handle_t *h, const char *symname);

int main(int argc, char **argv, char **envp) {
	int fd;
	handle_t h;
	struct iovec iov = {};
	struct stat st;
	long trap, orig;
	int status, pid;
	char *args[2];
	if (argc < 3) {
		printf("Usage: %s <program> <function>\n", argv[0]);
		exit(0);
	}

	if ((h.exec = strdup(argv[1])) == NULL) {
		perror("strdup");
		exit(-1);
	}

	args[0] = h.exec;
	args[1] = NULL;

	if ((h.symname = strdup(argv[2])) == NULL) {
		perror("strdup");
		exit(-1);
	}

	if ((fd = open(argv[1], O_RDONLY)) < 0) {
		perror("open");
		exit(-1);
	}

	if (fstat(fd, &st) < 0) {
		perror("fstat");
		exit(-1);
	}
		
	h.mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (h.mem == MAP_FAILED) {
		perror("mmap");
		exit(-1);
	}
	h.ehdr = (Elf64_Ehdr *)h.mem;
	h.phdr = (Elf64_Phdr *) (h.mem + h.ehdr->e_phoff);
	h.shdr = (Elf64_Shdr *) (h.mem + h.ehdr->e_shoff);

	if (h.mem[0] != 0x7f || strcmp((char *)&h.mem[1], "ELF") < 0) {
		printf("%s is not an ELF file\n", h.exec);
		exit(-1);
	}

	if (h.ehdr->e_type != ET_EXEC) {
		printf("%s is not an ELF executable\n", h.exec);
		exit(-1);
	}

	if (h.ehdr->e_shstrndx == 0 || h.ehdr->e_shoff == 0 || h.ehdr->e_shnum == 0) {
		printf("section header table not found\n");
		exit(-1);
	}
	
	if ((h.symaddr = lookup_symbol(&h, h.symname)) == 0) {
		printf("unabled to find symbol: %s not found in executable\n", h.symname);
		exit(-1);
	}
	close(fd);
	
	if ((pid = fork()) < 0) {
		perror("fork");
		exit(-1);
	}

	if (pid == 0) {
		if (ptrace(PTRACE_TRACEME, pid, NULL, NULL) < 0) {
			perror("PTRACE_TRACEME");
			exit(-1);
		}
		execve(h.exec, args, envp);
		exit(0);
	}
	wait(&status);
	printf("Beginning analysis of pid: %d at 0x%lx\n", pid, h.symaddr);
	
	/* PTRACE_PEEKTEXT returns the data read, not a status code. So, we need to check errno for error handling. */
	errno = 0;	
	orig = ptrace(PTRACE_PEEKTEXT, pid, h.symaddr, NULL);
	if (errno != 0) {
    		perror("PTRACE_PEEKTEXT");
		exit(-1);
	}		

	printf("Original instruction at 0x%lx: 0x%lx\n", h.symaddr, orig);
		
	// setting breakpoint
	trap = 0xd4200000;

	if (ptrace(PTRACE_POKETEXT, pid, h.symaddr, trap) < 0) {
		perror("PTRACE_POKETEXT");
		exit(-1);
	}
	
trace:
	if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
		perror("PTRACE_CONT");
		exit(-1);
	}

	wait(&status);
	CHECK_CHILD_STATUS(status);
	iov.iov_base = &h.regs;
	iov.iov_len = sizeof(h.regs);
	if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
		if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
			perror("PTRACE_GETREGSET");
			exit(-1);
		
		}
		printf("\nExecutable %s (pid: %d) has hit breakpoint 0x%lx\n", h.exec, pid, h.symaddr);
		
		for (size_t reg_num = 0; reg_num < 31; reg_num++) {
			printf("x%zd: %llx\n", reg_num, h.regs.regs[reg_num]); 
		}
		printf("sp: %llx\npc: %llx\n", h.regs.sp, h.regs.pc);
		
		printf("\nPlease hit any key to continue: ");
		getchar();
		
		printf("Restoring instruction: 0x%lx\n", orig);
		if (ptrace(PTRACE_POKETEXT, pid, h.symaddr, orig) < 0) {
			perror("PTRACE_POKETEXT");
			exit(-1);
		}
			
		h.regs.pc -= 4;
		printf("Adjusted $PC: 0x%llx\n", h.regs.pc);
		
		if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
			printf("PTRACE_SETREGSET failed. Errno: %d\n", errno);
			perror("PTRACE_SETREGSET");
			exit(-1);
		}

		
		if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0) {
			perror("PTRACE_SINGLESTEP");
			exit(-1);
		}
    		
		wait(NULL);
		printf("$PC after single step: 0x%llx\n", h.regs.pc);

		if (ptrace(PTRACE_POKETEXT, pid, h.symaddr, trap) < 0) {
    			perror("PTRACE_POKETEXT (reset breakpoint)");
    			exit(-1);
		}

		if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
			perror("PTRACE_CONT");
			exit(-1);
		}

		wait(&status);
		CHECK_CHILD_STATUS(status);
	}
	
	if (WIFEXITED(status)) {
		printf("Completed tracing pid: %d\n", pid);
		exit(0);
	}

	goto trace;
}

Elf64_Addr lookup_symbol(handle_t *h, const char *symname) {
	int i, j;
	char *strtab;
	Elf64_Sym *symtab;
	for (i = 0; i < h->ehdr->e_shnum; i++) {
		if (h->shdr[i].sh_type == SHT_SYMTAB) {
			strtab = (char *)&h->mem[h->shdr[h->shdr[i].sh_link].sh_offset];
			symtab = (Elf64_Sym *)&h->mem[h->shdr[i].sh_offset];
			printf("Symbol table found at offset: %ld\n", h->shdr[i].sh_offset);
			for (j = 0; j < h->shdr[i].sh_size/sizeof(Elf64_Sym); j++) {
				printf("%d: %s\n", j, &strtab[symtab[j].st_name]);
				if (strcmp(&strtab[symtab[j].st_name], symname) == 0) {
					printf("Found symbol %s at address 0x%lx\n", symname, symtab[j].st_value);
					return (symtab[j].st_value);
					symtab++;
				}
			}			
		}
	}
	return 0;
}


