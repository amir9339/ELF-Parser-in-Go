// Note that this tool can only parse 32bit ELFs

/*
To Do:
-- Add user input handler (Get file an option from options list)
-- Symbol tables support
-- Note tables support (?)
*/

package main

import (
	"bytes"
	"encoding/binary" // imports as package "cli"
)

const (
	// ELF Consts
	ELFMAGIC  = "\177ELF"
	EI_NIDENT = 16 // Size of e_ident array

	// Print Consts
	ELF_HEADER_FILE_INFO_PRINTLINE    = "Class:\t\t\t\t\t%s\nData:\t\t\t\t\t%s\nVersion:\t\t\t\t%d\nOS/ABI:\t\t\t\t\t%s\nABI Version:\t\t\t\t%d\nFile Type:\t\t\t\t%s\nSupported machine:\t\t\t%s\n"
	ELF_HEADER_OFFSETS_INFO_PRINTLINE = "File version:\t\t\t\t0x%x\nEntry point address:\t\t\t0x%x\nStart of program headers:\t\t%d (bytes into file)\nStart of section headers:\t\t%d (bytes into file)\nFlags\t\t\t\t\t0x%d\nSize of this header:\t\t\t%d (bytes)\nSize of program header:\t\t\t%d (bytes)\nNumber of program headers: \t\t%d\nSize of section headers\t\t\t%d (bytes)\nNumber of section headers:\t\t%d\nSection header string table index:\t%d\n\n"
	PROGRAM_HEADER_GENERAL_INFO       = "ELF file type is %s\nEntry point 0x%x\nThere are %d program headers, starting at offset %d\n\nProgram headers:\n"
	PROGRAM_HEADER_TABLE_COLUMNS      = "  Type\tOffset\tVirtAddr\tPhysAddr\tFileSiz\tMemSiz\tFlags\tAlign\n"
	PROGRAM_HEADER_TABLE_ROW          = "  %s\t0x%x\t0x%x\t0x%x\t0x%x\t0x%x\t%d\t%s\n"
	SECTION_HEADER_GENERAL_INFO       = "There are %d section headers, starting at offset 0x%s:\n\nSection Headers:\n"
	SECTION_HEADER_TABLE_COLUMNS      = "  Name\tType\tAddress\tOffset\tSize\tEntSize\tFlags\tLink\tInfo\tAlign\n"
	SECTION_HEADER_TABLE_ROW          = "  %s\t%s\t0x%x\t0x%x\t0x%x\t0x%x\t0x%x\t0x%x\t0x%x\t%s\n"

	// Tables formating const
	PADDING         = 3
	TABLE_SEPERATOR = ' '
)

func main() {

	filename, display_all, display_elf_header, display_program_header, display_section_header := GetUserInput()

	// Open file and read it as a byte slice
	file_bytes, err := ReadFileBytes(filename)

	if err != nil {
		panic(err)
	}

	// Parse ELF header - Required for every option
	elf_header := Elf32_Ehdr{}
	binary.Read(bytes.NewBuffer(file_bytes), binary.LittleEndian, &elf_header)

	if display_elf_header {
		// Print ELF header info
		PrintElfHeaderData(elf_header)
	}

	if display_program_header {
		// Parse ELF Program Header table
		ph_entries := ParseProgramHeaderTable(file_bytes, elf_header)
		PrintProgramHeaderData(elf_header, ph_entries)
	}

	if display_section_header {
		// Parse ELF Section Header table
		sh_entries := ParseSectionHeaderTable(file_bytes, elf_header)
		PrintSectionHeaderData(elf_header, sh_entries)
	}

	if display_all {
		PrintElfHeaderData(elf_header)
		PrintProgramHeaderData(elf_header, ParseProgramHeaderTable(file_bytes, elf_header))
		PrintSectionHeaderData(elf_header, ParseSectionHeaderTable(file_bytes, elf_header))
	}
}
