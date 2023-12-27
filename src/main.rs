
use std::env;
use std::io::{SeekFrom, Seek};
use std::process::exit;
use std::fs::{read_to_string, File};
use nix::libc::{PTRACE_ATTACH, PTRACE_DETACH};
use regex::Regex;
use std::io::prelude::*;
use std::convert::TryFrom;
use nix;

fn read_maps_info(pid: &String) -> Vec<(u64, u64, String)> {
    let re = Regex::new(r"^([a-f0-9]+)\-([a-f0-9]+)\s(...)").unwrap();
    let file_maps_path = format!("/proc/{pid}/maps");
    let maps_lines: Vec<String> = read_to_string(&file_maps_path).unwrap().lines().map(String::from).collect();
    let mut results: Vec<(u64, u64, String)> = Vec::new();
    for line in maps_lines {
        let captures_result  = re.captures(&line).unwrap().extract();
        let (_, [start_addr, end_addr, perms]) = captures_result;
        let start_addr = match u64::from_str_radix(start_addr, 16) {
            Ok(value) => value,
            Err(e) => {
                eprintln!("Error converting start_addr: {}", e);
                continue;             }
        };
        let end_addr: u64 = match u64::from_str_radix(end_addr, 16) {
            Ok(value) => value,
            Err(e) => {
                eprintln!("Error converting start_addr: {}", e);
                continue; 
            }
        };
     
        let infos: (u64, u64, String) = (
            start_addr,
            end_addr,
            perms.to_string(),
        );
        results.push(infos);
    }
    results
}



fn  main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print!("Usage {} <pid>", args[0]);
        exit(1);
    }
    let pid = &args[1]; 
    print!("THE PID IS : {}\n", pid);
    let maps_info: Vec<(u64, u64, String)> = read_maps_info(pid);

    unsafe { ptrace_attach(pid.parse::<i32>().unwrap_or(0)); } 


    let mut dump_file = match File::create("pid-dumper.dp") {
        Ok(file) => file,
        Err(e) => panic!("Couldn't create the file"),
    };
    let mut mem_file = match File::open(format!("/proc/{pid}/mem")) {
        Ok(file) => file,
        Err(e) => panic!("Couldn't open the file {}", e),
    };
    for (start_addr,end_addr,perm) in maps_info{
        if perm.contains("r") && perm.contains("w"){
            let addr_area = end_addr - start_addr;
            mem_file.seek(SeekFrom::Start(start_addr));
            let u_addr_area = match usize::try_from(addr_area)  {
                Ok(value) => value,
                Err(err) => panic!("couldn't convert u64 to usize: {}", err),
            };
            let mut buf = vec![0u8;u_addr_area];
            mem_file.read_exact(&mut buf);
            dump_file.write(&mut buf).expect("");
        }
    }
    unsafe { ptrace_detach(pid.parse::<i32>().unwrap_or(0)); }
}


unsafe fn ptrace_attach(pid: i32) -> i64 {
    nix::libc::ptrace(PTRACE_ATTACH, pid) 
}
unsafe fn ptrace_detach(pid: i32) -> i64 {
    nix::libc::ptrace(PTRACE_DETACH, pid) 
}
