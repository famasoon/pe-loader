use std::io::Read;
use std::mem::transmute;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree, WriteProcessMemory};
use winapi::um::processthreadsapi::{CreateThread, GetCurrentProcess};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::{ctypes::c_void, um::memoryapi::ReadProcessMemory};

pub fn fill_structure_from_array<T, U>(base: &mut T, arr: &[U]) -> usize {
    let handle = unsafe { GetCurrentProcess() };
    let mut bytes_writttten: usize = 0;
    let res = unsafe {
        WriteProcessMemory(
            handle,
            base as *mut _ as *mut c_void,
            arr as *const _ as *const c_void,
            std::mem::size_of::<T>(),
            &mut bytes_writttten,
        )
    };

    if res == 0 {
        panic!("Failed to write to process memory: {}", unsafe {
            GetLastError()
        });
    }

    bytes_writttten
}

pub fn fill_structure_from_memory<T>(
    dest: &mut T,
    src: *const c_void,
    prochandle: *mut c_void,
) -> usize {
    let bytestoread: usize = std::mem::size_of::<T>();
    let mut buffer: Vec<u8> = vec![0; bytestoread];
    let mut byteswritten = 0;

    let _ = unsafe {
        ReadProcessMemory(
            prochandle,
            src,
            buffer.as_mut_ptr() as *mut c_void,
            bytestoread,
            &mut byteswritten,
        )
    };
    fill_structure_from_array(dest, &buffer);

    return byteswritten;
}

pub fn get_headers_size(buffer: &Vec<u8>) -> usize {
    if buffer.len() < 2 {
        panic!("file size is less than 2")
    }
    let magic = &buffer[0..2];
    let magicstring = String::from_utf8_lossy(magic);
    if magicstring == "MZ" {
        if buffer.len() < 64 {
            panic!("file size is less than 64")
        }
        let ntoffset = &buffer[60..64];
        unsafe {
            let offset = std::ptr::read(ntoffset.as_ptr() as *const i32) as usize;

            let bitversion = &buffer[offset + 4 + 20..offset + 4 + 20 + 2];
            let bit = std::ptr::read(bitversion.as_ptr() as *const u16);
            if bit == 523 {
                let index = offset + 24 + 60;
                let headerssize = &buffer[index as usize..index as usize + 4];
                let size = std::ptr::read(headerssize.as_ptr() as *const i32);
                return size as usize;
            } else if bit == 267 {
                let index = offset + 24 + 60;
                let headerssize = &buffer[index as usize..index as usize + 4];
                let size = std::ptr::read(headerssize.as_ptr() as *const i32);
                return size as usize;
            } else {
                panic!("invalid bit version");
            }
        }
    } else {
        panic!("its not a pe file");
    }
}

pub fn get_image_size(buffer: &Vec<u8>) -> usize {
    if buffer.len() < 2 {
        panic!("file size is less than 2")
    }
    let magic = &buffer[0..2];
    let magicstring = String::from_utf8_lossy(magic);
    if magicstring == "MZ" {
        if buffer.len() < 64 {
            panic!("file size is less than 64")
        }
        let ntoffset = &buffer[60..64];
        unsafe {
            let offset = std::ptr::read(ntoffset.as_ptr() as *const i32) as usize;

            let bitversion = &buffer[offset + 4 + 20..offset + 4 + 20 + 2];
            let bit = std::ptr::read(bitversion.as_ptr() as *const u16);
            if bit == 523 {
                let index = offset + 24 + 60 - 4;
                let headerssize = &buffer[index as usize..index as usize + 4];
                let size = std::ptr::read(headerssize.as_ptr() as *const i32);
                //println!("size of image: {:x?}",size);
                return size as usize;
            } else if bit == 267 {
                let index = offset + 24 + 60 - 4;
                let headerssize = &buffer[index as usize..index as usize + 4];
                let size = std::ptr::read(headerssize.as_ptr() as *const i32);
                //println!("size of image: {:x?}",size);
                return size as usize;
            } else {
                panic!("invalid bit version");
            }
        }
    } else {
        panic!("its not a pe file");
    }
}

pub fn read_string_from_memory(baseaddress: *const u8, phandle: *mut c_void) -> String {
    let mut temp: Vec<u8> = vec![0; 100];
    let mut bytesread: usize = 0;

    let mut i = 0;
    loop {
        let _ = unsafe {
            ReadProcessMemory(
                phandle,
                (baseaddress as isize + i) as *const c_void,
                (temp.as_mut_ptr() as usize + i as usize) as *mut c_void,
                1,
                &mut bytesread,
            )
        };

        if temp[i as usize] == 0 {
            break;
        }
        i += 1;
    }
    let dllname = String::from_utf8_lossy(&temp);
    dllname.to_string()
}

#[derive(Debug, Default, Clone)]
struct MyImageThunkData64 {
    address: [u8; 8],
}

use std::fs::File;

pub fn reflective_loader64(phandle: *mut c_void, buffer: Vec<u8>) {
    let headerssize = get_headers_size(&buffer);
    let imagesize = get_image_size(&buffer);

    let baseptr = unsafe {VirtualAlloc(std::ptr::null_mut(), imagesize, 0x1000, 0x40)};

    unsafe {WriteProcessMemory(
        phandle,
        baseptr,
        buffer.as_ptr() as *const c_void,
        headerssize,
        std::ptr::null_mut(),
    )};

    let mut dosheader = ImageDosHeader::default();
    fill_structure_from_array(&mut dosheader, &buffer);

    let mut ntheader = ImageNtHeaders64::default();
    fill_structure_from_memory(
        &mut ntheader,
        (baseptr as isize + dosheader.e_lfanew as isize) as *const c_void,
        phandle,
    );

    let mut sections: Vec<ImageSectionHeader> =
        vec![ImageSectionHeader::default(); ntheader.file_header.number_of_sections as usize];

    for i in 0..sections.len() {
        fill_structure_from_memory(
            &mut sections[i],
            (baseptr as usize
                + dosheader.e_lfanew as usize
                + std::mem::size_of_val(&ntheader) as usize
                + (i * std::mem::size_of::<ImageSectionHeader>()) as usize)
                as *const c_void,
            phandle,
        );

        let temp: Vec<u8> = buffer[sections[i].pointer_to_raw_data as usize
            ..(sections[i].pointer_to_raw_data as usize + sections[i].size_of_raw_data as usize)]
            .to_vec();

        unsafe {WriteProcessMemory(
            phandle,
            (baseptr as usize + sections[i].virtual_address as usize) as *mut c_void,
            temp.as_ptr() as *const c_void,
            sections[i].size_of_raw_data as usize,
            std::ptr::null_mut(),
        )};
    }

    if ntheader.optional_header.import_table.size > 0 {
        let mut ogfirstthunkptr =
            baseptr as usize + ntheader.optional_header.import_table.virtual_address as usize;

        loop {
            let mut import = ImageImportDescriptor::default();

            fill_structure_from_memory(&mut import, ogfirstthunkptr as *const c_void, phandle);

            if import.name == 0 && import.first_thunk == 0 {
                break;
            }

            let dllname = read_string_from_memory(
                (baseptr as usize + import.name as usize) as *const u8,
                phandle,
            );

            //println!("DLL Name: {}",dllname);
            let dllhandle = unsafe {LoadLibraryA(dllname.as_bytes().as_ptr() as *const i8)};

            let mut thunkptr =
                baseptr as usize + import.characteristics_or_original_first_thunk as usize;

            let mut i = 0;

            loop {
                let mut thunkdata = MyImageThunkData64::default();

                fill_structure_from_memory(
                    &mut thunkdata,
                    (thunkptr as usize) as *const c_void,
                    phandle,
                );

                if thunkdata.address == [0; 8]
                    && u64::from_ne_bytes(thunkdata.address.try_into().unwrap())
                        < 0x8000000000000000
                {
                    break;
                }

                let offset = u64::from_ne_bytes(thunkdata.address.try_into().unwrap());

                let funcname = read_string_from_memory(
                    (baseptr as usize + offset as usize + 2) as *const u8,
                    phandle,
                );

                if funcname != "" {
                    let funcaddress =
                        unsafe {GetProcAddress(dllhandle, funcname.as_bytes().as_ptr() as *const i8)};

                    let finalvalue = i64::to_ne_bytes(funcaddress as i64);

                    unsafe {WriteProcessMemory(
                        phandle,
                        (baseptr as usize + import.first_thunk as usize + (i * 8)) as *mut c_void,
                        finalvalue.as_ptr() as *const c_void,
                        finalvalue.len(),
                        std::ptr::null_mut(),
                    )};
                }
                i += 1;

                thunkptr += 8;
            }

            ogfirstthunkptr += std::mem::size_of::<ImageImportDescriptor>();
        }
    }

    // fixing base relocations

    if ntheader.optional_header.base_relocation_table.size > 0 {
        let diffaddress = baseptr as usize - ntheader.optional_header.image_base as usize;
        let mut relocptr = baseptr as usize
            + ntheader
                .optional_header
                .base_relocation_table
                .virtual_address as usize;

        loop {
            let mut reloc1 = MyImageBaseRelocation::default();

            fill_structure_from_memory(&mut reloc1, relocptr as *const c_void, phandle);

            if reloc1.sizeof_block == 0 {
                break;
            }

            let entries = (reloc1.sizeof_block - 8) / 2;

            for i in 0..entries {
                let mut relocoffset: [u8; 2] = [0; 2];

                unsafe { ReadProcessMemory(
                    phandle,
                    (relocptr + 8 + (i * 2) as usize) as *const c_void,
                    relocoffset.as_mut_ptr() as *mut c_void,
                    2,
                    std::ptr::null_mut(),
                ) };

                let temp = u16::from_ne_bytes(relocoffset.try_into().unwrap());

                let type1 = temp >> 12;
                if type1 == 0xA {
                    // 1&0=0  0&0=0
                    let finaladdress = baseptr as usize
                        + reloc1.virtual_address as usize
                        + (temp & 0x0fff) as usize;

                    let mut ogaddress: [u8; 8] = [0; 8];

                    unsafe { ReadProcessMemory(
                        phandle,
                        finaladdress as *const c_void,
                        ogaddress.as_mut_ptr() as *mut c_void,
                        8,
                        std::ptr::null_mut(),
                    ) };

                    let fixedaddress =
                        isize::from_ne_bytes(ogaddress.try_into().unwrap()) + diffaddress as isize;

                    unsafe { WriteProcessMemory(
                        phandle,
                        finaladdress as *mut c_void,
                        fixedaddress.to_ne_bytes().as_ptr() as *const c_void,
                        8,
                        std::ptr::null_mut(),
                    ) };
                }
            }

            relocptr += reloc1.sizeof_block as usize;
        }
    }

    let threadres = unsafe { CreateThread(
        std::ptr::null_mut(),
        0,
        Some(transmute(
            (baseptr as usize + ntheader.optional_header.address_of_entry_point as usize)
                as *mut c_void,
        )),
        std::ptr::null_mut(),
        0,
        std::ptr::null_mut(),
    ) };

    unsafe { WaitForSingleObject(threadres, 10000) };

    unsafe { VirtualFree(baseptr, 0, 0x00008000) };
}

fn main() {
    let mut buffer: Vec<u8> = Vec::new();
    let mut fd = File::open(r#"C:\windows\notepad.exe"#).unwrap();

    let _ = fd.read_to_end(&mut buffer);

    unsafe {
        reflective_loader64(GetCurrentProcess(), buffer.clone());
    }
}

#[derive(Debug, Clone, Default)]
pub struct MyImageBaseRelocation {
    virtual_address: u32,
    sizeof_block: u32,
}

pub fn get_string_fromu8_array(arr: &mut [u8]) -> String {
    let mut temp = String::new();

    for i in 0..arr.len() {
        if arr[i] == 0 {
            return temp;
        } else {
            temp.push(arr[i] as u8 as char);
        }
    }

    temp
}

pub fn get_string_fromi8_array(arr: &mut [i8]) -> String {
    let mut temp = String::new();

    for i in 0..arr.len() {
        if arr[i] == 0 {
            return temp;
        } else {
            temp.push(arr[i] as u8 as char);
        }
    }

    temp
}

#[derive(Debug, Default, Clone)]
#[repr(C)]

pub struct ImageDosHeader {
    e_magic: [u8; 2],  // Magic number
    e_cblp: u16,       // Bytes on last page of file
    e_cp: u16,         // Pages in file
    e_crlc: u16,       // Relocations
    e_cparhdr: u16,    // Size of header in paragraphs
    e_minalloc: u16,   // Minimum extra paragraphs needed
    e_maxalloc: u16,   // Maximum extra paragraphs needed
    e_ss: u16,         // Initial (relative) SS value
    e_sp: u16,         // Initial SP value
    e_csum: u16,       // Checksum
    e_ip: u16,         // Initial IP value
    e_cs: u16,         // Initial (relative) CS value
    e_lfarlc: u16,     // File address of relocation table
    e_ovno: u16,       // Overlay number
    e_res1: [u16; 4],  // Reserved words
    e_oemid: u16,      // OEM identifier (for e_oeminfo)
    e_oeminfo: u16,    // OEM information, e_oemid specific
    e_res2: [u16; 10], // Reserved words
    e_lfanew: i32,     // File address of new exe header
}

#[derive(Clone, Default, Debug)]
#[repr(C)]
pub struct ImageSectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    characteristics: u32,
}

impl ImageSectionHeader {
    fn getsecname(&mut self) -> String {
        String::from_utf8_lossy(&self.name).to_string()
    }
}

#[repr(C)]
pub union chars_or_originalfirstthunk {
    characteristics: u32,
    original_first_thunk: u32,
}

#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct ImageImportDescriptor {
    characteristics_or_original_first_thunk: u32,

    time_date_stamp: u32,

    forwarder_chain: u32,

    name: u32,

    first_thunk: u32,
}

#[repr(C)]
pub union IMAGE_THUNK_DATA32 {
    pub forwarder_string: u32,

    pub function: u32,

    pub ordinal: u32,

    pub address_of_data: u32,
}

#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct ImageExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32,
    pub base: u32,
    pub number_of_fnctions: u32,
    pub number_of_names: u32,
    pub address_of_functions: u32,     // RVA from base of image
    pub address_of_names: u32,         // RVA from base of image
    pub address_of_name_ordinals: u32, // RVA from base of image
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
pub struct ImageOptionalHeader64 {
    magic: u16,

    major_linker_version: u8,

    minor_linker_version: u8,

    size_of_code: u32,

    size_of_initialized_data: u32,

    size_of_uninitialized_data: u32,

    address_of_entry_point: u32,

    base_of_code: u32,

    image_base: i64,

    section_alignment: u32,

    file_alignment: u32,

    major_operating_system_version: u16,

    minor_operating_system_version: u16,

    major_image_version: u16,

    minor_image_version: u16,

    major_subsystem_version: u16,

    minor_subsystem_version: u16,

    win32_version_value: u32,

    size_of_image: u32,

    size_of_headers: u32,

    check_sum: u32,

    subsystem: u16,

    dll_characteristics: u16,

    size_of_stack_reserve: u64,

    size_of_stack_commit: u64,

    size_of_heap_reserve: u64,

    size_of_heap_commit: u64,

    loader_flags: u32,

    number_of_rva_and_sizes: u32,

    export_table: ImageDataDirectory,

    import_table: ImageDataDirectory,

    resource_table: ImageDataDirectory,

    exception_table: ImageDataDirectory,

    certificate_table: ImageDataDirectory,

    base_relocation_table: ImageDataDirectory,

    debug: ImageDataDirectory,

    architecture: ImageDataDirectory,

    global_ptr: ImageDataDirectory,

    tlstable: ImageDataDirectory,
    load_config_table: ImageDataDirectory,
    bound_import: ImageDataDirectory,

    iat: ImageDataDirectory,

    delay_import_descriptor: ImageDataDirectory,
    clrruntime_header: ImageDataDirectory,

    reserved: ImageDataDirectory,
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
pub struct ImageOptionalHeader32 {
    magic: u16,

    major_linker_version: u8,

    minor_linker_version: u8,

    size_of_code: u32,

    size_of_initialized_data: u32,

    size_of_uninitialized_data: u32,

    address_of_entry_point: u32,

    base_of_code: u32,

    // PE32 contains this additional field
    base_of_data: u32,

    image_base: u32,

    section_alignment: u32,

    file_alignment: u32,

    major_operating_system_version: u16,

    minor_operating_system_version: u16,

    major_image_version: u16,

    minor_image_version: u16,

    major_subsystem_version: u16,

    minor_subsystem_version: u16,

    win32_version_value: u32,

    size_of_image: u32,

    size_of_headers: u32,

    check_sum: u32,

    subsystem: u32,

    dll_characteristics: u16,

    size_of_stack_reserve: u32,

    size_of_stack_commit: u32,

    size_of_heap_reserve: u32,

    size_of_heap_commit: u32,

    loader_flags: u32,

    number_of_rva_and_sizes: u32,

    export_table: ImageDataDirectory,

    import_table: ImageDataDirectory,

    resource_table: ImageDataDirectory,

    exception_table: ImageDataDirectory,

    certificate_table: ImageDataDirectory,

    base_relocation_table: ImageDataDirectory,

    debug: ImageDataDirectory,

    architecture: ImageDataDirectory,

    global_ptr: ImageDataDirectory,

    tlstable: ImageDataDirectory,
    load_config_table: ImageDataDirectory,
    bound_import: ImageDataDirectory,

    iat: ImageDataDirectory,

    delay_import_descriptor: ImageDataDirectory,
    clrruntime_header: ImageDataDirectory,

    reserved: ImageDataDirectory,
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
pub struct ImageFileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
pub struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
pub struct ImageNtHeaders32 {
    signature: u32,

    file_header: ImageFileHeader,

    optional_header: ImageOptionalHeader32,
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
pub struct ImageNtHeaders64 {
    signature: u32,

    file_header: ImageFileHeader,

    optional_header: ImageOptionalHeader64,
}
