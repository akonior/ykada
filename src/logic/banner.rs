const GREEN: &str = "\x1b[1;32m";
const BOLD_WHITE: &str = "\x1b[1;37m";
const RESET: &str = "\x1b[0m";

pub fn banner() -> String {
    [
        format!("  {GREEN}╻ ╻╻┏ ┏━┓╺┳┓┏━┓{RESET}"),
        format!("  {GREEN}┗┳┛┣┻┓┣━┫ ┃┃┣━┫{RESET}"),
        format!("  {GREEN} ╹ ╹ ╹╹ ╹╺┻┛╹ ╹{RESET}  {BOLD_WHITE}YubiKey Cardano Wallet{RESET}"),
    ]
    .join("\n")
        + "\n"
}
