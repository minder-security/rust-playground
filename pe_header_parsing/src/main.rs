mod pe_helper; // This will import the pe_headers.rs file

use pe_helper::{DosHeader, PeHeader, CoffHeader, OptionalHeader, parse_dos_header, parse_pe_header}; // Importing specific structs
use std::io::Read;

fn display_dos_header(dos: &DosHeader) {
    println!("{}", "-".repeat(40));
    println!("DOS Header");
    println!("{}", "-".repeat(40));
    println!("[e_magic]  Magic: 0x{:02X} 0x{:02X} ({})", dos.e_magic[0], dos.e_magic[1], String::from_utf8_lossy(&dos.e_magic[0..2]));
    println!("[e_lfanew] Offset to NT Header: 0x{:X}", dos.e_lfanew);
    println!("{}", "-".repeat(40));
}

fn display_coff_header(coff: &CoffHeader) {
    println!("{}", "-".repeat(40));
    println!("COFF Header");
    println!("{}", "-".repeat(40));
    println!("Machine: 0x{:04X}", coff.machine);
    println!("Number of Sections: {}", coff.number_of_sections);
    println!("Timestamp: {}", coff.timestamp);
    println!("Symbol Table: 0x{:X}", coff.pointer_to_symbol_table);
    println!("Characteristics: 0x{:04X}", coff.characteristics);
    println!("{}", "-".repeat(40));
}

fn display_optional_header(optional: &OptionalHeader) {
    println!("{}", "-".repeat(40));
    println!("Optional Header");
    println!("{}", "-".repeat(40));
    println!("Magic: 0x{:04X}", optional.magic);
    println!("Size of Code: {}", optional.size_of_code);
    println!("Size of Initialized Data: {}", optional.size_of_initialized_data);
    println!("Address of Entry Point: 0x{:08X}", optional.address_of_entry_point);
    println!("Image Base: 0x{:08X}", optional.image_base);
    println!("Section Alignment: {}", optional.section_alignment);
    println!("File Alignment: {}", optional.file_alignment);
    println!("{}", "-".repeat(40));
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <path-to-exe>", args[0]);
        std::process::exit(1);
    }

    let path = &args[1];
    let mut file = std::fs::File::open(path)?;
    let mut buffer = [0u8; 64]; // Read the DOS header (64 bytes)
    file.read_exact(&mut buffer)?;

    let dos_header = parse_dos_header(&buffer)?;

    display_dos_header(&dos_header);

    let pe_header = parse_pe_header(&mut file, dos_header.e_lfanew)?;
    
    display_coff_header(&pe_header.coff_header);
    display_optional_header(&pe_header.optional_header);

    Ok(())
}