use std::io;
use std::io::{Seek, Read, SeekFrom};

#[repr(C)]
#[derive(Default)]
pub struct DosHeader {
    pub e_magic: [u8; 2], 
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: u32,
}

#[repr(C)]
#[derive(Default)]
pub struct PeHeader {
    pub signature: [u8; 4],
    pub coff_header: CoffHeader,
    pub optional_header: OptionalHeader,
}

#[repr(C)]
#[derive(Default)]
pub struct CoffHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub timestamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[repr(C)]
#[derive(Default)]
pub struct OptionalHeader {
    pub magic: u16,
    pub linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}


// Functions

pub fn parse_dos_header(buf: &[u8]) -> io::Result<DosHeader> {
    Ok(DosHeader {
        e_magic: [buf[0], buf[1]],
        e_lfanew: u32::from_le_bytes([buf[60], buf[61], buf[62], buf[63]]),
        ..Default::default()
    })
}

pub fn parse_pe_header(file: &mut std::fs::File, offset: u32) -> io::Result<PeHeader> {
    file.seek(SeekFrom::Start(offset as u64))?;

    let mut signature = [0u8; 4];
    file.read_exact(&mut signature)?;

    if signature != [0x50, 0x45, 0x00, 0x00] {
        return Err(io::Error::new(io::ErrorKind::InvalidData,  "Invalid PE signature"));
    }

    let mut coff_header = [0u8; 20];
    file.read_exact(&mut coff_header)?;

    let coff = CoffHeader {
        machine: u16::from_le_bytes([coff_header[0], coff_header[1]]),
        number_of_sections: u16::from_le_bytes([coff_header[2], coff_header[3]]),
        timestamp: u32::from_le_bytes([coff_header[4], coff_header[5], coff_header[6], coff_header[7]]),
        ..Default::default()
    };

    let mut optional_header = [0u8; 224];
    file.read_exact(&mut optional_header)?;

    let optional = OptionalHeader {
        magic: u16::from_le_bytes([optional_header[0], optional_header[1]]),
        linker_version: optional_header[2],
        ..Default::default()
    };

    Ok(PeHeader {
        signature,
        coff_header: coff,
        optional_header: optional,
    })
}