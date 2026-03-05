const GREEN: &str = "\x1b[1;32m";
const RESET: &str = "\x1b[0m";

pub fn banner() -> String {
    [
        format!("  {GREEN}╻ ╻╻┏ ┏━┓╺┳┓┏━┓{RESET}"),
        format!("  {GREEN}┗┳┛┣┻┓┣━┫ ┃┃┣━┫{RESET}"),
        format!("  {GREEN} ╹ ╹ ╹╹ ╹╺┻┛╹ ╹{RESET}"),
    ]
    .join("\n")
}
