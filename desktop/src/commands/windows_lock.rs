/// Verify the current Windows account password; PIN is not an account password.
/// This is a UI access gate, not database encryption or protection against the OS user.
#[cfg(windows)]
pub fn verify(password:String)->Result<(),String>{
    use std::ffi::c_void;
    #[link(name="secur32")]
    extern "system" {fn GetUserNameExW(format:u32,name:*mut u16,size:*mut u32)->u8;}
    #[link(name="advapi32")]
    extern "system" {fn LogonUserW(user:*const u16,domain:*const u16,password:*const u16,kind:u32,provider:u32,token:*mut *mut c_void)->i32;}
    #[link(name="kernel32")]
    extern "system" {fn CloseHandle(handle:*mut c_void)->i32;}
    let mut length=0u32;
    unsafe{GetUserNameExW(2,std::ptr::null_mut(),&mut length);}
    if length==0||length>4096{return Err("无法读取当前 Windows 身份".into());}
    let mut buffer=vec![0u16;length as usize];
    if unsafe{GetUserNameExW(2,buffer.as_mut_ptr(),&mut length)}==0{return Err("无法读取当前 Windows 身份".into());}
    let name=String::from_utf16_lossy(&buffer[..length as usize]);
    let (domain,user)=name.split_once('\\').ok_or("Windows 账号名称不支持")?;
    let user:Vec<u16>=user.encode_utf16().chain(Some(0)).collect();
    let domain:Vec<u16>=domain.encode_utf16().chain(Some(0)).collect();
    if password.is_empty()||password.contains('\0')||password.len()>1024{return Err("请输入 Windows 账号密码（不是 PIN）".into());}
    let mut secret:Vec<u16>=password.encode_utf16().chain(Some(0)).collect();
    let mut token=std::ptr::null_mut();
    let ok=unsafe{LogonUserW(user.as_ptr(),domain.as_ptr(),secret.as_ptr(),2,0,&mut token)};
    for word in &mut secret{unsafe{std::ptr::write_volatile(word,0);}}
    if ok==0{return Err("Windows 身份验证失败，请使用当前 Windows 账号密码（不是 PIN）".into());}
    unsafe{CloseHandle(token);}
    Ok(())
}
#[cfg(not(windows))]
pub fn verify(_password:String)->Result<(),String>{Err("应用锁当前仅支持 Windows".into())}
