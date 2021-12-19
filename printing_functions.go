package main

import (
	"fmt" // imports as package "cli"
	"os"
	"text/tabwriter"
)

func PrintElfHeaderData(elf_header Elf32_Ehdr) {
	_, class, endian, version, osabi, abi_version := ParseIdent(elf_header.E_ident[:])
	object_type, machine := ParseElfHeader(elf_header)

	fmt.Printf(ELF_HEADER_FILE_INFO_PRINTLINE, class, endian, version, osabi, abi_version, object_type, machine)
	fmt.Printf(ELF_HEADER_OFFSETS_INFO_PRINTLINE,
		elf_header.E_version,
		elf_header.E_entry,
		elf_header.E_phoff,
		elf_header.E_shoff,
		elf_header.E_flags,
		elf_header.E_ehsize,
		elf_header.E_phentsize,
		elf_header.E_phnum,
		elf_header.E_shentsize,
		elf_header.E_shnum,
		elf_header.E_shstrndx)
}

func PrintProgramHeaderData(elf_header Elf32_Ehdr, ph_entries []ReadableProgramHeaderTableEntry) {
	/*
		This is the print function for Program Header extraction.
		It prints Program header tables as well as more basic info about the ELF
	*/

	w := tabwriter.NewWriter(os.Stdout, 0, 0, PADDING, TABLE_SEPERATOR, tabwriter.TabIndent|tabwriter.Debug)

	object_type, _ := ParseElfHeader(elf_header)

	fmt.Printf(PROGRAM_HEADER_GENERAL_INFO,
		object_type,
		elf_header.E_entry,
		elf_header.E_phnum,
		elf_header.E_phoff,
	)
	fmt.Fprint(w, PROGRAM_HEADER_TABLE_COLUMNS)

	// Iterate over entries slice
	for _, entry := range ph_entries[1:] {
		fmt.Fprintf(w, PROGRAM_HEADER_TABLE_ROW, entry.Type, entry.Offset, entry.VirtAddr, entry.PhysAddr, entry.FileSiz, entry.MemSiz, entry.Align, entry.Flags)
	}
	w.Flush()
}

func PrintSectionHeaderData(elf_header Elf32_Ehdr, sh_entries []ReadableSectionHeaderTableEntry) {
	/*
		This is the print function for Section Header extraction.
		It prints Section header tables as well as more basic info about the ELF
	*/

	w := tabwriter.NewWriter(os.Stdout, 0, 0, PADDING, TABLE_SEPERATOR, tabwriter.TabIndent|tabwriter.Debug)

	sh_offset := fmt.Sprintf("%x", elf_header.E_shoff)
	fmt.Printf(SECTION_HEADER_GENERAL_INFO, elf_header.E_shnum, sh_offset)
	fmt.Fprint(w, SECTION_HEADER_TABLE_COLUMNS)

	for _, entry := range sh_entries[1:] {
		fmt.Fprintf(w, SECTION_HEADER_TABLE_ROW, entry.Name, entry.Type, entry.Address, entry.Offset, entry.Size, entry.Link, entry.Info, entry.AddrAlign, entry.EntSize, entry.Flags)
	}
	w.Flush()
}
