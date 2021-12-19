package main

import (
	"bytes"
	"encoding/binary"
)

func ParseIdent(e_ident_array []byte) (bool, string, string, int, string, int) {
	/*
		/This function is used to parse the first member of the ELF header: e_ident which is 16 bytes long array.
		It holds the File's magic value as well as other info about the binary.
		Note that EI_PAD and EI_NIDENT are reserved and set to zero so it doesn't parse them.
	*/

	is_elf := false   // If magic present
	var class string  // ELF class (32/64 bit)
	var endian string // Endian style
	var version int   // File version
	var osabi string
	var abi_version int // ABI version of the file

	ei_mag := string(e_ident_array[:4]) // Slice first four bytes, represents magic value
	ei_class := e_ident_array[4]
	ei_data := e_ident_array[5]
	ei_version := e_ident_array[6]
	ei_osabi := e_ident_array[7]
	ei_abiversion := e_ident_array[8]

	// Check if ELF magic is present
	if ei_mag == ELFMAGIC {
		is_elf = true
	} else {
		panic("Its not an ELF file\n")
	}

	switch ei_class {
	case 0:
		class = "None"
	case 1:
		class = "ELF32"
	case 2:
		class = "ELF64"
	default:
		panic("Invalid class\n")
	}

	switch ei_data {
	case 0:
		endian = "Unknown"
	case 1:
		endian = "Little-endian"
	case 2:
		endian = "Big-endian"
	default:
		panic("Invalid endian\n")
	}

	// Doesn't support *all* different abi values from the table specified in:
	//     http://www.sco.com/developers/gabi/latest/ch4.eheader.html
	switch ei_osabi {
	case 0:
		osabi = "UNIX - System V"
	case 1:
		osabi = "HP-UX"
	case 2:
		osabi = "NetBSD"
	case 3:
		osabi = "GNU"
	case 4:
		osabi = "Linux"
	case 5:
		osabi = "Sun Solaris"
	case 6:
		osabi = "AIX"
	case 7:
		osabi = "FreeBSD"
	case 8:
		osabi = "TRU64 UNIX"
	case 11:
		osabi = "Novell Modesto"
	default:
		osabi = "Could not detect OS ABI"
	}

	version = int(ei_version)
	abi_version = int(ei_abiversion)

	return is_elf, class, endian, version, osabi, abi_version
}

func ParseElfHeader(elf_header Elf32_Ehdr) (string, string) {
	/*
		This function parses the first 2 members of the Elf header for 32bit ELFs only.
		The other members are numerical so there is no point to extract them.
			File version
			Virtual address of the entry function
			Program header offset
			Section header offset
			Size in bytes of each entry in the file's program header table
			Number of entries in the program header table
			Size in bytes of each entry in the file's section header table
			Number of entries in the section header table
			Section table haeder index of the entry associated with the section name string table
	*/

	var object_type string // Object file type
	var machine string     // Required arch

	// There are 4 other values that are system / processor specific so I didn't include them
	switch elf_header.E_type {
	case 0:
		object_type = "No file type"
	case 1:
		object_type = "Relocatable file"
	case 2:
		object_type = "Executable file"
	case 3:
		object_type = "Shared object file"
	case 4:
		object_type = "Core file"
	default:
		object_type = "Couldn't detect file type"
	}

	// Because there are many optional values in here I included only the most important values
	switch elf_header.E_machine {
	case 0:
		machine = "No machine"
	case 3:
		machine = "Intel 80386"
	case 20:
		machine = "PowerPC"
	case 21:
		machine = "64-bit PowerPC"
	case 40:
		machine = "ARM 32-bit architecture"
	case 62:
		machine = "AMD x86-64 architecture"
	default:
		machine = "Couldn't detect machine type"
	}

	return object_type, machine
}

func ParseProgramHeaderTableEntry(ph_entry Elf32_Phdr) ReadableProgramHeaderTableEntry {
	/*
		This function converts ProgramHeader struct to readable entry.
		It returns a struct of the type ReadableProgramHeaderTableEntry
	*/

	// Create entry struct instance and fill with known values (Values that doesn't requires parsing)
	entry := ReadableProgramHeaderTableEntry{
		Offset:   ph_entry.P_offset,
		VirtAddr: ph_entry.P_vaddr,
		PhysAddr: ph_entry.P_paddr,
		FileSiz:  ph_entry.P_filesz,
		MemSiz:   ph_entry.P_memsz,
		Align:    ph_entry.P_align}

	// Values taken from: https://docs.oracle.com/cd/E19683-01/816-1386/6m7qcoblk/index.html#chapter6-69880
	switch ph_entry.P_type {
	case 0:
		entry.Type = "NULL"
	case 1:
		entry.Type = "LOAD"
	case 2:
		entry.Type = "DYNAMIC"
	case 3:
		entry.Type = "INTERP"
	case 4:
		entry.Type = "NOTE"
	case 5:
		entry.Type = "SHLIB"
	case 6:
		entry.Type = "PHDR"
	default:
		entry.Type = "Unknown"
	}

	// Values taken from: https://docs.oracle.com/cd/E19683-01/816-1386/6m7qcoblk/index.html#chapter6-tbl-39
	switch ph_entry.P_flags {
	case 0:
		entry.Flags = "None"
	case 1:
		entry.Flags = "X"
	case 2:
		entry.Flags = "W"
	case 3:
		entry.Flags = "W X"
	case 4:
		entry.Flags = "R"
	case 5:
		entry.Flags = "R X"
	case 6:
		entry.Flags = "R W"
	case 7:
		entry.Flags = "R W X"

	default:
		entry.Flags = "Could not detect"
	}

	return entry
}

func ParseProgramHeaderTable(file_bytes []byte, elf_header Elf32_Ehdr) []ReadableProgramHeaderTableEntry {
	/*
		This function parses PH Table and extract the data from it. The columns are:
			Type, offset, VAddr, PAddr, FileSz, MemSz
			It returns a slice of Readable Ph entries
		It gets program header table offset and number of entries in it.
	*/

	entries := make([]ReadableProgramHeaderTableEntry, 1)

	// Iterate each entry in program header table
	ph_offset := int(elf_header.E_phoff)         // Table offset in file
	ph_entry_size := int(elf_header.E_phentsize) // Size of each entry in table
	var i uint16                                 // Counter
	var entry_offset int                         // Current entry pointer
	for i = 0; i < elf_header.E_phnum; i++ {
		p_header := Elf32_Phdr{}                            // Declare p_header
		entry_offset = ph_offset + (ph_entry_size * int(i)) // Current entry offset
		binary.Read(bytes.NewBuffer(file_bytes[entry_offset:]), binary.LittleEndian, &p_header)
		readable_ph_entry := ParseProgramHeaderTableEntry(p_header)
		entries = append(entries, readable_ph_entry)
	}

	return entries
}

func ParseSectionHeaderTableEntry(sh_entry Elf32_Shdr) ReadableSectionHeaderTableEntry {
	/*
		This function converts SectionHeader struct to a readable entry.
	*/

	// Create entry struct instance and fill with known values (Values that doesn't requires parsing)
	entry := ReadableSectionHeaderTableEntry{
		Address:   sh_entry.SH_addr,
		Offset:    sh_entry.SH_offset,
		Size:      sh_entry.SH_size,
		Link:      sh_entry.SH_link,
		Info:      sh_entry.SH_info,
		AddrAlign: sh_entry.SH_addralign,
		EntSize:   sh_entry.SH_entsize,
		NameIndex: sh_entry.SH_name}

	switch sh_entry.SH_type {
	case 0:
		entry.Type = "NULL"
	case 1:
		entry.Type = "PROGBITS"
	case 2:
		entry.Type = "SYMTAB"
	case 3:
		entry.Type = "STRTAB"
	case 4:
		entry.Type = "RELA"
	case 5:
		entry.Type = "HASH"
	case 6:
		entry.Type = "DYNAMIC"
	case 7:
		entry.Type = "NOTE"
	case 8:
		entry.Type = "NOBITS"
	case 9:
		entry.Type = "REL"
	case 10:
		entry.Type = "SHLIB"
	case 11:
		entry.Type = "DYNSYM"
	case 12:
		entry.Type = "LOPROC, HIPROC"
	case 13:
		entry.Type = "LOUSER"
	case 14:
		entry.Type = "HIUSER"
	default:
		entry.Type = "Unknown"
	}

	// There are more flags, they are specified in: https://docs.oracle.com/cd/E19683-01/817-3677/6mj8mbtc9/index.html#chapter6-10675
	switch sh_entry.SH_flags {
	case 1:
		entry.Flags = "WRITE"
	case 2:
		entry.Flags = "ALLOC"
	case 4:
		entry.Flags = "EXECINSTR"
	default:
		entry.Flags = "Unknown"
	}

	return entry
}

func ParseSectionHeaderTable(file_bytes []byte, elf_header Elf32_Ehdr) []ReadableSectionHeaderTableEntry {
	/*
		This function parses SH Table and extract the data from it. The columns are:
			Name, Type, Address, Offset, Size, Link, Info, AddrAlign, EntSize, Flags
		It also parses the section header string table and returns it.
	*/

	entries := make([]ReadableSectionHeaderTableEntry, 1)

	// Iterate each entry in section header table
	sh_offset := int(elf_header.E_shoff)         // Table offset in file
	sh_entry_size := int(elf_header.E_shentsize) // Size of each entry in table
	var i uint16                                 // Counter
	var entry_offset int                         // Current entry pointer
	for i = 0; i < elf_header.E_shnum; i++ {
		s_header := Elf32_Shdr{}                            // Declare s_header
		entry_offset = sh_offset + (sh_entry_size * int(i)) // Current entry offset
		binary.Read(bytes.NewBuffer(file_bytes[entry_offset:]), binary.LittleEndian, &s_header)
		readable_sh_entry := ParseSectionHeaderTableEntry(s_header)
		entries = append(entries, readable_sh_entry)
	}

	section_header_string_table_offset := entries[elf_header.E_shstrndx+1].Offset
	section_header_string_table_size := entries[elf_header.E_shstrndx+1].Size
	section_header_string_table := file_bytes[section_header_string_table_offset : section_header_string_table_offset+section_header_string_table_size]

	// Iterate over section header table and fill the name field
	for i := 0; i < len(entries); i++ {
		name_index := entries[i].NameIndex
		name_size := GetStringSize(section_header_string_table, int(name_index))
		name := string(section_header_string_table[name_index : int(name_index)+name_size])
		entries[i].Name = name
	}
	return entries
}
