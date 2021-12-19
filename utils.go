package main

import (
	"bufio"
	"flag"
	"os"
)

func GetStringSize(bytes_array []byte, offset int) int {
	/*
		This function find the size of a string in a null terminated strings byte array.
		It returns the size of the string.
	*/

	// Iterate each byte in the array until a null byte is found
	for i := offset; i < len(bytes_array); i++ {
		if bytes_array[i] == 0 {
			return i - offset
		}
	}
	return len(bytes_array)
}

func ReadFileBytes(filename string) ([]byte, error) {

	// Open file
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	stats, statsErr := file.Stat()
	if statsErr != nil {
		return nil, statsErr
	}

	// Get file size for making bytes slice
	var size int64 = stats.Size()
	bytes := make([]byte, size)

	bufr := bufio.NewReader(file)
	_, err = bufr.Read((bytes))

	return bytes, err
}

func GetUserInput() (string, bool, bool, bool, bool) {
	/*
		This function uses the flag package to get user input.
		It returns the filename, and the boolean values for each option.
		No error checking for now because flag package does it anyway
	*/

	filename := flag.String("f", "", "Specify the ELF file to parse")
	display_all := flag.Bool("a", false, "Display the ELF file header")
	display_elf_header := flag.Bool("h", false, "Display the ELF file header")
	display_program_header := flag.Bool("l", false, "Display the ELF program headers")
	display_section_header := flag.Bool("S", false, "Display the ELF section headers")

	flag.Parse()
	return *filename, *display_all, *display_elf_header, *display_program_header, *display_section_header
}
