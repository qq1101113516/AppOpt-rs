use std::env;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-env-changed=APPOPT_EBPF_OBJ");

    let obj = env::var("APPOPT_EBPF_OBJ").expect(
        "APPOPT_EBPF_OBJ 未设置：请用 ./build-rs.sh 构建，它会先编译 eBPF 再把对象路径传入以内嵌",
    );
    assert!(
        Path::new(&obj).is_file(),
        "APPOPT_EBPF_OBJ 指向的文件不存在: {obj}"
    );

    println!("cargo:rerun-if-changed={obj}");
    println!("cargo:rustc-env=APPOPT_EBPF_OBJ={obj}");
    println!("cargo:warning=embedded eBPF object: {obj}");
}
