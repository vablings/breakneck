mod pages;

use chacha20::ChaCha20;
// Import relevant traits
use chacha20::cipher::{KeyIvInit, StreamCipher};
use iced_x86::{Decoder, Instruction};


use pelite::pe64::Pe;
use pelite::pe64::PeView;

use core::slice;
use std::sync::LazyLock;
use std::{ffi::c_void, net::TcpStream, sync::Mutex, time::Duration};

use windows_sys::Win32::{
    Foundation::{EXCEPTION_ACCESS_VIOLATION, NTSTATUS},
    System::{
        Diagnostics::Debug::*,
        LibraryLoader::GetModuleHandleA,
        Memory::{VirtualProtect, PAGE_EXECUTE, PAGE_NOACCESS, PAGE_READWRITE},
        SystemServices::{
            DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH,
        },
    },
};

pub static KEY: LazyLock<[u8; 32]> = LazyLock::new(|| rand::random());

pub fn chacha20(page: &mut [u8], address: u64) {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&address.to_le_bytes());
    let mut cipher = ChaCha20::new((&*KEY).into(), &nonce.into());
    cipher.apply_keystream(page);
}

fn dll_main() {
    let stream = TcpStream::connect("127.0.0.1:7331").unwrap();

    tracing_subscriber::fmt()
        .with_writer(Mutex::new(stream))
        .init();

    unsafe {
        AddVectoredExceptionHandler(1, Some(exception_handler));
    }

    encrypt_text_section();

    loop {
        std::thread::sleep(Duration::from_millis(1000));
    }
}

fn encrypt_text_section() {
    unsafe {
        let image_base = GetModuleHandleA(std::ptr::null());
        if image_base == std::ptr::null_mut() {
            panic!("Failed to get base module");
        }

        let pe_view = PeView::module(image_base as *const u8);

        let section = pe_view
            .section_headers()
            .iter()
            .find(|section| (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
            .expect("No sections with MEM_EXECUTE");

        let start = image_base as u64 + section.VirtualAddress as u64;
        let page_count = section.SizeOfRawData / 0x1000;

        find_pages();

        for i in 0..page_count {
            let page_address = start + i as u64 * 0x1000;
            //encrypt_page(page_address as _);
        }
        log::info!("Encrypted {} pages!", page_count);
    }
}

fn find_pages() {
    unsafe {
        let image_base = GetModuleHandleA(std::ptr::null());
        if image_base == std::ptr::null_mut() {
            panic!("Failed to get base module");
        }
        let pe_view = PeView::module(image_base as *const u8);
        let section = pe_view
            .section_headers()
            .iter()
            .find(|section| (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
            .expect("No sections with MEM_EXECUTE");
        
        // Use VirtualSize instead of SizeOfRawData for in-memory size
        let section_size = if section.VirtualSize > 0 {
            section.VirtualSize
        } else {
            section.SizeOfRawData
        };
        
        let text = slice::from_raw_parts(
            (image_base as u64 + section.VirtualAddress as u64) as *const u8,
            section_size as usize,
        );
        
        let mut decoder = Decoder::with_ip(64, text, section.VirtualAddress.into(), 0);
        let mut straddler_count = 0;
        let mut total_instructions = 0;
        
        while decoder.can_decode() {
            let mut instr = Instruction::default();
            decoder.decode_out(&mut instr);
            
            let start = instr.ip();
            let len = instr.len() as u64;
            let end = start + len - 1; // End is inclusive (last byte of instruction)
            
            // Check if instruction crosses page boundary
            let start_page = start & !0xFFF;
            let end_page = end & !0xFFF;
            
            total_instructions += 1;
            
            if start_page != end_page {
                straddler_count += 1;
                log::info!(
                    "[Straddler] {:#x} - {:#x} ({} bytes) {} | Pages: {:#x} -> {:#x}",
                    start,
                    start + len,
                    len,
                    instr,
                    start_page,
                    end_page
                );
            } 
        }
        
        log::info!(
            "Found {} page-straddling instructions out of {} total ({:.2}%)",
            straddler_count,
            total_instructions,
            (straddler_count as f64 / total_instructions as f64) * 100.0
        );
    }
}
fn encrypt_page(page_address: usize) {
    unsafe {
        log::info!("Encrypting page {page_address:#x}");
        let mut old_protect = 0;
        VirtualProtect(
            page_address as *mut c_void,
            0x1000,
            PAGE_READWRITE,
            &mut old_protect,
        );
        let page_slice = slice::from_raw_parts_mut(page_address as *mut u8, 0x1000);
        chacha20(page_slice, page_address as u64);

        VirtualProtect(
            page_address as *mut c_void,
            0x1000,
            PAGE_NOACCESS,
            &mut old_protect,
        );

        PAGE_TRACKER.insert_or_update(page_address as u64, true, false);
    }
}

fn decrypt_page(page_address: usize) {
    unsafe {
        log::info!("Decrypting page {page_address:#x}");

        let mut old_protect = 0;
        VirtualProtect(
            page_address as *mut c_void,
            0x1000,
            PAGE_READWRITE,
            &mut old_protect,
        );
        let page_slice = slice::from_raw_parts_mut(page_address as *mut u8, 0x1000);
        chacha20(page_slice, page_address as u64);
        VirtualProtect(
            page_address as *mut c_void,
            0x1000,
            PAGE_EXECUTE,
            &mut old_protect,
        );

        PAGE_TRACKER.insert_or_update(page_address as u64, false, false);
    }
}

unsafe extern "system" fn exception_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    let exception = (*(*exception_info).ExceptionRecord).ExceptionCode as NTSTATUS;
    if exception == EXCEPTION_ACCESS_VIOLATION {
        let page_address =
            (*(*exception_info).ExceptionRecord).ExceptionInformation[1] / 0x1000 * 0x1000;
        if let Some(instance) = PAGE_TRACKER.get(page_address as u64) {
            if instance.is_encrypted() {
                decrypt_page(page_address);

                PAGE_TRACKER.get_all_unencrypted().iter().for_each(|&addr| {
                    encrypt_page(addr as usize);
                });

                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }
    EXCEPTION_CONTINUE_SEARCH
}

use crate::pages::PAGE_TRACKER;
use u32 as DWORD;
type LPVOID = *mut core::ffi::c_void;

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
pub unsafe extern "stdcall" fn DllMain(module: usize, reason: DWORD, _: LPVOID) -> u8 {
    match reason {
        DLL_PROCESS_ATTACH => {
            std::thread::spawn(move || dll_main());
            1
        }
        DLL_PROCESS_DETACH | DLL_THREAD_ATTACH | DLL_THREAD_DETACH => 1,
        _ => 0,
    }
}
