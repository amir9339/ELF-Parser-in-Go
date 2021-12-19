package main

type Elf32_Ehdr struct {
	E_ident     [EI_NIDENT]byte
	E_type      uint16
	E_machine   uint16
	E_version   uint32
	E_entry     uint32
	E_phoff     uint32
	E_shoff     uint32
	E_flags     uint32
	E_ehsize    uint16
	E_phentsize uint16
	E_phnum     uint16
	E_shentsize uint16
	E_shnum     uint16
	E_shstrndx  uint16
}

type Elf32_Phdr struct {
	P_type   uint32
	P_offset uint32
	P_vaddr  uint32
	P_paddr  uint32
	P_filesz uint32
	P_memsz  uint32
	P_flags  uint32
	P_align  uint32
}

type Elf32_Shdr struct {
	SH_name      uint32
	SH_type      uint32
	SH_flags     uint32
	SH_addr      uint32
	SH_offset    uint32
	SH_size      uint32
	SH_link      uint32
	SH_info      uint32
	SH_addralign uint32
	SH_entsize   uint32
}

type ReadableProgramHeaderTableEntry struct {
	Type     string
	Offset   uint32
	VirtAddr uint32
	PhysAddr uint32
	FileSiz  uint32
	MemSiz   uint32
	Flags    string
	Align    uint32
}

type ReadableSectionHeaderTableEntry struct {
	NameIndex uint32
	Name      string
	Type      string
	Address   uint32
	Offset    uint32
	Size      uint32
	Link      uint32
	Info      uint32
	AddrAlign uint32
	EntSize   uint32
	Flags     string
}
