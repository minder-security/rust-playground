use std::fs::File;
use std::io::{self, Read};
use std::mem::size_of;

#[repr(C)]
#[derive(Debug)]
struct Elf64Header {
    e_ident: [u8; 16],     // Magic number and other info
    e_type: u16,           // Object file type
    e_machine: u16,        // Architecture
    e_version: u32,        // Object file version
    e_entry: u64,          // Entry point virtual address
    e_phoff: u64,          // Program header table file offset
    e_shoff: u64,          // Section header table file offset
    e_flags: u32,          // Processor-specific flags
    e_ehsize: u16,         // ELF header size in bytes
    e_phentsize: u16,      // Program header table entry size
    e_phnum: u16,          // Program header table entry count
    e_shentsize: u16,      // Section header table entry size
    e_shnum: u16,          // Section header table entry count
    e_shstrndx: u16,       // Section header string table index
}


fn main() {
    let path = "your_binary_file";
    match parse_elf_header(path) {
        Ok(header) => {
            println!("Parsed ELF Header: {:#?}", header);
        }
        Err(e) => {
            eprintln!("Failed to parse ELF header: {}", e);
        }
    }
}
