extern crate libcryptopro_sys as csp;
use csp::*;

// include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use std::env;
use std::fs;
use std::io::prelude::*;
use std::fs::File;
use std::io;

const BUFSIZE: usize = 1024;
const GR3411LEN: DWORD = 64;
fn main() -> Result<(), i32> {
    // return result
    test_sign_over_bind()
}

fn HandleError(s: &str) {
    let mut err: u32;
    unsafe {
        err = GetLastError();
    };
    println!("Error number     : {:X}\n", err);
    println!("Error description: {}\n", s);
    // if(!err)
    //     err = 1;
    // exit(err);
}

fn test_sign_over_bind() -> Result<(), i32> {
    // PKCS_7_ASN_ENCODING
    // const MY_ENCODING_TYPE (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

    println!("Signature data");

    // let contents = fs::read_to_string(&filename).expect("Something went wrong reading the file");
    let mut hProv: HCRYPTPROV = 0;
    let hprov = &mut hProv as *mut HCRYPTPROV;
    unsafe {
        // todo this function only for the CryptAcquireContextW for UNICODE
        let mut CONTAINER = String::from("\\\\.\\HDIMAGE\\testzm");
        CONTAINER.push('\0');
        // convert vector to i32 from char
        let mut cont_vec = Vec::new();
        for ch in CONTAINER.chars() {
            cont_vec.push(ch as i32);
            println!("ch {}", ch as i32);
        }
        for it in cont_vec.iter() {
            println!("i32 {}", it);
        }
        let status = CryptAcquireContextW(
            hprov,
            // 0 as LPCWSTR, //
            cont_vec.as_ptr(), //NULL,
            0 as LPCWSTR,      //NULL,
            PROV_GOST_2012_256,
            0,
        );
        println!("Status crypto acquire context:{} hprov {}", status, *hprov);
        if (status != 0) {
            println!("CSP context acquired.");
        } else {
            HandleError("Error during CryptAcquireContext.");
        }
    }
    //--------------------------------------------------------------------
    // Получение открытого ключа подписи. Этот открытый ключ будет
    // использоваться получателем хэша для проверки подписи.
    // В случае, когда получатель имеет доступ к открытому ключю
    // отправителя с помощью сертификата, этот шаг не нужен.

    let mut hKey : HCRYPTKEY = 0;
    // pub fn CryptGetUserKey(hProv: HCRYPTPROV, dwKeySpec: DWORD, phUserKey: *mut HCRYPTKEY) -> BOOL;
    unsafe {
    let status = CryptGetUserKey(*hprov, AT_SIGNATURE, &mut hKey as *mut HCRYPTKEY );
    if (status != 0) {
        println!("The signature key has been acquired.");
    } else {
        HandleError("Error during CryptGetUserKey for signkey.");
    }
    }

    //--------------------------------------------------------------------
    // Экпорт открытого ключа. Здесь открытый ключ экспортируется в
    // PUBLICKEYBOLB для того, чтобы получатель подписанного хэша мог
    // проверить подпись. Этот BLOB может быть записан в файл и передан
    // другому пользователю.
    let mut dwBlobLen : u32 = 0;
    unsafe {

    if (CryptExportKey(
            hKey,
            0,
            PUBLICKEYBLOB,
            0,
            0 as *mut BYTE, // pbData
            &mut dwBlobLen as *mut DWORD) != 0)
    {
        println!("Size of the BLOB for the public key determined.");
    }
    else
    {
        HandleError("Error computing BLOB length.");
    }
    println!("Size dwBloblen {}", dwBlobLen);
    }


    //--------------------------------------------------------------------
    // Распределение памяти под pbKeyBlob.
    // Сам экспорт в ключевой BLOB.
    let mut pbKeyBlob:Vec<BYTE> = vec![0; dwBlobLen as usize];
    unsafe {
    if (CryptExportKey(
            hKey,
            0,
            PUBLICKEYBLOB,
            0,
            pbKeyBlob.as_ptr() as *mut BYTE, // pbData
            &mut dwBlobLen as *mut DWORD) != 0)
    {
        println!("Contents have been written to the BLOB.");
    }
    else
    {
        HandleError("Error during CryptExportKey.");
    }
    println!("Size dwBloblen {} pbKeyBlob {:?}", dwBlobLen, pbKeyBlob);
    }

    // Creating hash object
    let mut hHash: HCRYPTHASH = 0;
    let hash = &mut hHash as *mut HCRYPTHASH;
    unsafe {
        let status = CryptCreateHash(hProv, CALG_GR3411_2012_256, 0, 0, hash);
        println!("Status crypto create hash:{}", status);
        if (status == 0) {
            CryptReleaseContext(hProv, 0);
            HandleError("Error during CryptCreateHash.");
        }
    }

    //--------------------------------------------------------------------
    // Передача параметра HP_OID объекта функции хэширования.
    //--------------------------------------------------------------------
    // Определение размера BLOBа и распределение памяти.
    //--------------------------------------------------------------------
    let mut cbHash : u32 = 0;
    unsafe {

    if (CryptGetHashParam(hHash,
                          HP_OID,
                          0 as *mut BYTE,
                          &mut cbHash as *mut DWORD,
                          0) != 0)
    {
        println!("Size of the BLOB determined.");
    }
    else
    {
        HandleError("Error computing BLOB length.");
    }
    }

    let mut pbHash:Vec<BYTE> = vec![0; cbHash as usize];
    if (pbHash.len() < (cbHash as usize))
    {
        HandleError("Out of memory. \n");
    }

    unsafe {

    // Копирование параметра HP_OID в pbHash.
    if (CryptGetHashParam(hHash,
                          HP_OID,
                          pbHash.as_ptr() as *mut BYTE,
                          &mut cbHash as *mut DWORD,
                          0) != 0)
    {
        println!("Parameters have been written to the pbHash.");
    }
    else
    {
        HandleError("Error during CryptGetHashParam.");
    }
    }

    //--------------------------------------------------------------------
    // Вычисление криптографического хэша буфера.
    unsafe {
    let buf = "The data that is to be hashed and signed.";

    if (CryptHashData(
            hHash,
            // pbBuffer,
            buf.as_ptr() as *mut BYTE,
            // dwBufferLen,
            buf.len() as DWORD,
            0) != 0)
    {
        println!("The data buffer has been hashed.\n");
    }
    else
    {
        HandleError("Error during CryptHashData.");
    }
    }

    // Определение размера подписи и распределение памяти.
    // DWORD dwSigLen;
    
    // pub fn CryptSignHashW(
    //     hHash: HCRYPTHASH,
    //     dwKeySpec: DWORD,
    //     szDescription: LPCWSTR,
    //     dwFlags: DWORD,
    //     pbSignature: *mut BYTE,
    //     pdwSigLen: *mut DWORD,
    // ) -> BOOL;

    let mut dwSigLen : u32 = 0;
    unsafe {
    if (CryptSignHashW(
            hHash,
            AT_SIGNATURE,
            0 as LPCWSTR,// NULL,
            0,
            0 as *mut BYTE,
            &mut dwSigLen as *mut DWORD
            ) != 0)
    {
        println!("Signature length {} found.", dwSigLen);
    }
    else
    {
        HandleError("Error during CryptSignHash.");
    }
    }
    //--------------------------------------------------------------------
    // Распределение памяти под буфер подписи.

    let mut pbSignature:Vec<BYTE> = vec![0; dwSigLen as usize];
    if (pbSignature.len() < (dwSigLen as usize))
    {
        HandleError("Out of memory for the signature.");
    }

    unsafe {

    // Подпись объекта функции хэширования.
    if (CryptSignHashW(
            hHash,
            AT_SIGNATURE,
            0 as LPCWSTR,// NULL,
            0,
            pbSignature.as_ptr() as *mut BYTE,
            &mut dwSigLen as *mut DWORD
            ) != 0)
    {
        println!("pbSignature is the hash signature.\n");
    }
    else
    {
        HandleError("Error during CryptSignHash.");
    }
    }
    let mut file = File::create("signature.txt").unwrap();
    // file.write_all(pbSignature.as_ptr());
    let mut str = String::new();
    for ch in pbSignature.iter() {
        println!("Char {}", ch);
       str.push(*ch as char); 
    }
    file.write_all(pbSignature.as_ref());

    // //if(!fopen_s(&signature, "signature.txt", "w+b" ))
    // if (!(signature = fopen("signature.txt", "w+b")))
    //     HandleError("Problem opening the file signature.txt\n");

    // fwrite(pbSignature, 1, dwSigLen, signature);
    // fclose(signature);

    // Уничтожение объекта функции хэширования.
    if (hHash != 0) {
        unsafe {
        CryptDestroyHash(hHash);
        }
    }

    println!("The hash object has been destroyed.\n");
    println!("The signing phase of this program is completed.\n\n");

    //--------------------------------------------------------------------
    // Во второй части программы проверяется подпись.
    // Чаще всего проверка осуществляется в случае, когда различные
    // пользователи используют одну и ту же программу. Хэш, подпись,
    // а также PUBLICKEYBLOB могут быть прочитаны из файла, e-mail сообщения
    // или из другого источника.

    // Здесь используюся определенные ранее pbBuffer, pbSignature,
    // szDescription, pbKeyBlob и их длины.

    // Содержимое буфера pbBuffer представляет из себя некоторые
    // подписанные ранее данные.

    // Указатель szDescription на текст, описывающий данные, подписывается.
    // Это тот же самый текст описания, который был ранее передан
    // функции CryptSignHash.

    //--------------------------------------------------------------------
    // Получение откытого ключа пользователя, который создал цифровую подпись,
    // и импортирование его в CSP с помощью функции CryptImportKey. Она
    // возвращает дескриптор открытого ключа в hPubKey.

    // pub fn CryptImportKey(
    //     hProv: HCRYPTPROV,
    //     pbData: *const BYTE,
    //     dwDataLen: DWORD,
    //     hPubKey: HCRYPTKEY,
    //     dwFlags: DWORD,
    //     phKey: *mut HCRYPTKEY,
    // ) -> BOOL;

    let mut hPubKey : HCRYPTKEY = 0;

    // let mut hProv: HCRYPTPROV = 0;
    // let hprov = &mut hProv as *mut HCRYPTPROV;
    unsafe {

    if (CryptImportKey(
            hProv,
            pbKeyBlob.as_ptr() as *mut BYTE, // pbData
            dwBlobLen,
            0,
            0,
            &mut hPubKey as *mut HCRYPTKEY) != 0)
    {
        println!("The key has been imported.");
    }
    else
    {
        HandleError("Public key import failed.");
    }
    }


    //--------------------------------------------------------------------
    // Создание нового объекта функции хэширования.
    // let mut hHash: HCRYPTHASH = 0;
    // let hash = &mut hHash as *mut HCRYPTHASH;
    unsafe {
        if (CryptCreateHash(hProv, CALG_GR3411_2012_256, 0, 0, hash) != 0) {
        println!("Status crypto create hash:0");
        println!("The hash object has been recreated.");
        } else {
            CryptReleaseContext(hProv, 0);
            HandleError("Error during CryptCreateHash.");
        }
    }

    //--------------------------------------------------------------------
    // Вычисление криптографического хэша буфера.
    unsafe {
    let buf = "The data that is to be hashed and signed.";

    if (CryptHashData(
            hHash,
            // pbBuffer,
            buf.as_ptr() as *mut BYTE,
            // dwBufferLen,
            buf.len() as DWORD,
            0) != 0)
    {
        println!("The data buffer has been hashed.\n");
    }
    else
    {
        HandleError("Error during CryptHashData.");
    }
    }

    //--------------------------------------------------------------------
    // Проверка цифровой подписи.
    unsafe {
    if (CryptVerifySignatureW(
            hHash,
            pbSignature.as_ptr() as *mut BYTE,
            dwSigLen,
            // &mut dwSigLen as *mut DWORD,
            hPubKey,
            // &mut hPubKey as *mut HCRYPTKEY,
            0 as LPCWSTR,// NULL,
            0) != 0)
    {
        println!("The signature has been verified.");
    }
    else
    {
        println!("Signature not validated!");
    }

    }

    // Уничтожение объекта функции хэширования.
    unsafe {

    if (hHash != 0) {
        CryptDestroyHash(hHash);
    }
    if (hKey != 0) {
        CryptDestroyKey(hKey);
    }
    if (hPubKey != 0){
        CryptDestroyKey(hPubKey);
    }
    // Освобождение дескриптора провайдера.
    if (hProv != 0) {
        CryptReleaseContext(hProv, 0);
    }
    }

    println!("Data and resources cleaned!");

    Ok(())
}

fn test_hash_over_bind() -> Result<(), i32> {
    let r: i32 = 32;

    let bIsReadingFailed: BOOL = FALSE as BOOL;
    let mut hProv: HCRYPTPROV = 0;
    let mut hHash: HCRYPTHASH = 0;
    let hFile: FILE;
    let rgbFile: [BYTE; BUFSIZE];
    let cbRead: DWORD = 0;
    // let rgbHash: [BYTE; GR3411LEN];
    let mut cbHash: DWORD = 0;
    const rgbDigits: &str = "0123456789abcdef";
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
    let mut buffer: [BYTE; 1024] = [0; 1024];
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
    let mut pbData: [BYTE; 64] = [0; 64];
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
        let it1: usize = (x >> 4) as usize;
        let it2: usize = (x & 0xf) as usize;
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
