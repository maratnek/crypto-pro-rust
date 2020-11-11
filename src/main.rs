extern crate libcryptopro_sys as csp;
use csp::*;

use std::env;
use std::fs;
use std::fs::File;
use std::io;
use std::io::prelude::*;

const BUFSIZE: usize = 1024;
const GR3411LEN: DWORD = 64;
fn main() -> Result<(), i32> {
    let r: i32 = 32;

    let bIsReadingFailed: BOOL = FALSE as BOOL;
    let mut hProv: HCRYPTPROV = 0;
    let mut hHash: HCRYPTHASH = 0;
    let hFile: FILE;
    let rgbFile: [BYTE; BUFSIZE];
    let cbRead: DWORD = 0;
    // let rgbHash: [BYTE; GR3411LEN];
    let mut cbHash: DWORD = 0;
    const rgbDigits:&str = "0123456789abcdef";
    let i: DWORD;

    let argc = env::args().count();
    let argv: Vec<String> = env::args().collect();
    println!("Argv {}, {}", argv[0], argv[0]);
    if (argc != 2 || argv[1] == "") {
        HandleError("The file name is absent.\n");
        return Err(1);
    }

    println!("Reading args success: count {} argv: {:?}", argc, argv);

    let filename = argv[1].clone();
    println!("In file {}", filename);

    let mut file = File::open(&filename).unwrap();
    file.sync_all();
    let mut buffer: [BYTE;1024] = [0; 1024];
    let mut n = file.read(&mut buffer);
    println!("End print buf");

    let contents = fs::read_to_string(&filename).expect("Something went wrong reading the file");
    let hprov = &mut hProv as *mut HCRYPTPROV;
    unsafe {
        // todo this function only for the CryptAcquireContextW for UNICODE
        let status = CryptAcquireContextW(
            hprov,
            0 as LPCWSTR, //NULL,
            0 as LPCWSTR, //NULL,
            PROV_GOST_2012_256,
            CRYPT_VERIFYCONTEXT,
        );
        println!("Status crypto acquire context:{} hprov {}", status, *hprov);
        if (status == 0) {
            HandleError("Status crypto acquire context");
        }
    }

    // println!("With text:\n{}", contents);
    let hash = &mut hHash as *mut HCRYPTHASH;
    unsafe {
        let status = CryptCreateHash(hProv, CALG_GR3411_2012_256, 0, 0, hash);
        println!("Status crypto create hash:{}", status);
        if (status == 0) {
            CryptReleaseContext(hProv, 0);
            HandleError("Status crypto acquire context");
        }
    }

    let mut i = 0;
    let count = n.unwrap();
        let d = &buffer as *const BYTE;
        unsafe {
            println!("Count {}", count);
            let status = CryptHashData(hHash, d, count as DWORD, 0);
            println!("Status CryptHashData:{}", status);
            if (status == 0) {
                CryptReleaseContext(hProv, 0);
                CryptDestroyHash(hHash);
                HandleError("CryptHashData failed");
            }
        }

    cbHash = GR3411LEN;
    let mut pbData:[BYTE; 64]  = [0; 64];
    println!("pbData: {:?}", pbData[0]);
    let rgbHash = pbData.as_mut_ptr() as *mut BYTE;
    println!("Arrray size: {}", cbHash);
    for x in pbData.iter() {
        print!("{} ", x);
    }
    unsafe {
        let mut countHash = &mut cbHash as *mut DWORD; 
        let status = CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, countHash, 0);
            if (status == 0) {
                CryptReleaseContext(hProv, 0);
                CryptDestroyHash(hHash);
                HandleError("CryptGetHashParam failed");
            }
    }

    println!("GR3411 hash of file {} is: ", argv[1]);
    println!("Arrray size: {}", cbHash);
    let mut arrChar: Vec<char> = Vec::new();
    for mut elem in rgbDigits.chars() {
        arrChar.push(elem); 
        print!("{}", elem); 
    }
    println!();
    for x in pbData.iter() {
        let it1 : usize = (x >> 4) as usize;
        let it2 : usize= (x & 0xf) as usize;
        print!("{}{} ", arrChar[it1], arrChar[it2]);
        // vDig[0].to_ascii_uppercase();
        // println!("iterators {:?} {:?}", vDig[it1].to_ascii_uppercase(), vDig[it2]);


        // print!("dig: {} {}", dig[it], dig[1]);

    }
    println!("Finish");
    // {
	//     printf("%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
    // }
    // printf("\n");

    Ok(())
}

fn HandleError(s: &str) {
    let mut err: u32;
    unsafe {
        err = GetLastError();
    };
    println!("Error number     : {}\n", err);
    println!("Error description: {}\n", s);
    // if(!err)
    //     err = 1;
    // exit(err);
}
