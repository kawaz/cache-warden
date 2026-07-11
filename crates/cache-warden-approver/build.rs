// draft-DR-0031 Phase 1.2: 単独バイナリでも Info.plist を有効にするため、Mach-O
// バイナリの `__TEXT,__info_plist` セクションに Info.plist を埋め込む。これで
// `.app` バンドル化を経由せず `LSUIElement=YES` (Dock Icon 非表示) が効く見込み。
// 効かなければ `.app` バンドル化 (Phase 1.2 の次ブロック) にフォールバックする。

fn main() {
    println!("cargo:rerun-if-changed=Info.plist");

    #[cfg(target_os = "macos")]
    {
        let manifest_dir =
            std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo");
        let plist_path = format!("{manifest_dir}/Info.plist");
        // Apple ld64 の `-sectcreate <segname> <sectname> <file>` を rustc の linker
        // argument 経由で渡す。rustc は `-C link-arg` を渡すと ld64 に転送する。
        println!("cargo:rustc-link-arg=-Wl,-sectcreate,__TEXT,__info_plist,{plist_path}");
    }
}
