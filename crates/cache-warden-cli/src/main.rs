use std::process;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const NAME: &str = "cache-warden";

fn print_help(to_stderr: bool) {
    let help_text = format!(
        "\
{NAME} {VERSION}
Manage and protect cache socket paths.

Usage:
    {NAME} [COMMAND] [OPTIONS]

Commands:
    (coming soon)

Options:
    --help           Show this help message
    --version        Show version"
    );
    if to_stderr {
        eprint!("{help_text}");
    } else {
        print!("{help_text}");
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.is_empty() {
        print_help(true);
        process::exit(1);
    }

    match args[0].as_str() {
        "--help" => {
            print_help(false);
            Ok(())
        }
        "--version" => {
            println!("{NAME} {VERSION}");
            Ok(())
        }
        _ => Err(format!("unknown command: {}", args[0])),
    }
}

fn main() {
    if let Err(e) = run() {
        if !e.is_empty() {
            eprintln!("{NAME}: {e}");
        }
        process::exit(1);
    }
}
