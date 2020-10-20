#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
#[link(name="ssp", kind ="dylib")]
#[link(name="capi10", kind ="dylib")]
#[link(name="capi20", kind ="dylib")]
#[link(name="rdrsup", kind ="dylib")]
#[link(name="pthread", kind ="dylib")]

use std::env;
use std::fs;

const BUFSIZE : usize = 1024;
const GR3411LEN : usize = 64;
fn main() ->  Result<(), i32> {
    let r : i32 = 32;

    let  bIsReadingFailed: BOOL = FALSE as BOOL;
    let hProv: HCRYPTPROV  = 0;
    let mut hHash: HCRYPTHASH  = 0;
    let hFile: FILE;
    let rgbFile: [BYTE; BUFSIZE];
    let cbRead: DWORD  = 0;
    let rgbHash: [BYTE; GR3411LEN];
    let cbHash: DWORD  = 0;
    // let rgbDigits: [CHAR] = "0123456789abcdef";
    let i: DWORD;

    let argc = env::args().count();
    let argv: Vec<String> = env::args().collect();
    println!("Argv {}, {}",argv[0], argv[0]);
    if(argc != 2 || argv[1] == "")
    {
       HandleError("The file name is absent.\n");
       return Err(1);
    }

    println!("Reading args success: count {} argv: {:?}",argc, argv);

    let filename = argv[1].clone();
    println!("In file {}", filename);

    let contents = fs::read_to_string(filename)
        .expect("Something went wrong reading the file");
        
    // if(!CryptAcquireContext(
	// &hProv,
	// NULL,
	// NULL,
	// PROV_GOST_2012_256,
	// CRYPT_VERIFYCONTEXT))
    // {
	// HandleError("CryptAcquireContext failed");
    // }
    // println!("With text:\n{}", contents);
    let hash = &mut hHash as *mut HCRYPTHASH;
    unsafe {
        !CryptCreateHash(hProv, CALG_GR3411_2012_256, 0, 0, hash);
        println!("With text:\n{}", contents);
    }
    // if()
    // {
	// CryptReleaseContext(hProv, 0);
	// HandleError("CryptCreateHash failed"); 
    // }
    Ok(())
}

fn HandleError(s: &str)
{
    // unsafe {let mut err: DWORD = GetLastError();};
    // println!("Error number     : {}\n", err);
    println!("Error description: {}\n", s);
    // if(!err) 
    //     err = 1;
    // exit(err);
}