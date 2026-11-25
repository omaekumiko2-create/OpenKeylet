#![cfg_attr(
    all(windows, not(debug_assertions), feature = "gui"),
    windows_subsystem = "windows"
)]

#[tokio::main]
async fn main() {
    match openkeylet::cli::run().await {
        Ok(0) => {}
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("OpenKeylet: {error:#}");
            std::process::exit(1);
        }
    }
}
