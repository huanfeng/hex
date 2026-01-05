use clap::Parser;
use crossterm::execute;
use crossterm::style::{Color, Print, ResetColor, SetBackgroundColor};
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use std::collections::HashMap;
use std::io::{self, Write};
#[cfg(windows)]
use windows::Win32::Globalization::GetUserDefaultLocaleName;

#[derive(Parser, Debug)]
#[command(name = "hex", version, about = "Base converter and calculator")]
struct Cli {
    #[arg(
        short = 'b',
        long = "bin",
        num_args = 0..=1,
        default_missing_value = "1",
        value_parser = parse_toggle_value
    )]
    bin: Option<bool>,

    #[arg(
        short = 'o',
        long = "oct",
        num_args = 0..=1,
        default_missing_value = "1",
        value_parser = parse_toggle_value
    )]
    oct: Option<bool>,

    #[arg(short = 'a', long = "all", help = "显示全部格式(Dec/Hex/Oct/Bin/Char)")]
    all: bool,

    #[arg(long = "dec", num_args = 0..=1, default_missing_value = "1", value_parser = parse_toggle_value)]
    dec: Option<bool>,

    #[arg(long = "hex", num_args = 0..=1, default_missing_value = "1", value_parser = parse_toggle_value)]
    hex: Option<bool>,

    #[arg(short = 'c', long = "char", help = "显示字符(单字节)")]
    show_char: bool,

    #[arg(short = 'l', long = "oneline", help = "单行输出")]
    oneline: bool,

    #[arg(short = 'i', long = "interactive", help = "交互模式")]
    interactive: bool,

    #[arg(long = "lang", value_name = "LANG", help = "语言: en/cn/zh/zh-CN")]
    lang: Option<String>,
}

#[derive(Clone, Copy, Debug)]
enum Op {
    Add,
    Sub,
    Mul,
    Div,
    And,
    Or,
    Xor,
    Not,
    Shl,
    Shr,
}

#[derive(Clone, Debug)]
enum Token {
    Number(i128),
    Ident(String),
    Op(Op),
    LParen,
    RParen,
}

#[derive(Clone, Copy, Debug)]
enum Lang {
    En,
    Zh,
}

enum Msg {
    ParseFailed(String),
    ColorParseFailed(String),
    ReplError(String),
    NoOutput,
    Cancelled,
    Bye,
    UnknownCommand(String),
    NoHistory(String),
    ReplStartFailed(String),
    InvalidLang(String),
}

fn msg(lang: Lang, msg: Msg) -> String {
    match (lang, msg) {
        (Lang::Zh, Msg::ParseFailed(err)) => format!("解析失败: {err}"),
        (Lang::En, Msg::ParseFailed(err)) => format!("Parse failed: {err}"),
        (Lang::Zh, Msg::ColorParseFailed(err)) => format!("颜色解析失败: {err}"),
        (Lang::En, Msg::ColorParseFailed(err)) => format!("Color parse failed: {err}"),
        (Lang::Zh, Msg::ReplError(err)) => format!("REPL 错误: {err}"),
        (Lang::En, Msg::ReplError(err)) => format!("REPL error: {err}"),
        (Lang::Zh, Msg::NoOutput) => "未选择输出格式".to_string(),
        (Lang::En, Msg::NoOutput) => "No output format selected".to_string(),
        (Lang::Zh, Msg::Cancelled) => "已取消".to_string(),
        (Lang::En, Msg::Cancelled) => "Cancelled".to_string(),
        (Lang::Zh, Msg::Bye) => "再见".to_string(),
        (Lang::En, Msg::Bye) => "Bye".to_string(),
        (Lang::Zh, Msg::UnknownCommand(cmd)) => format!("未知命令: {cmd}"),
        (Lang::En, Msg::UnknownCommand(cmd)) => format!("Unknown command: {cmd}"),
        (Lang::Zh, Msg::NoHistory(err)) => format!("历史记录失败: {err}"),
        (Lang::En, Msg::NoHistory(err)) => format!("History error: {err}"),
        (Lang::Zh, Msg::ReplStartFailed(err)) => format!("无法启动 REPL: {err}"),
        (Lang::En, Msg::ReplStartFailed(err)) => format!("Failed to start REPL: {err}"),
        (Lang::Zh, Msg::InvalidLang(value)) => format!("不支持的语言: {value}"),
        (Lang::En, Msg::InvalidLang(value)) => format!("Unsupported language: {value}"),
    }
}

fn main() {
    let (cli, expression, lang) = split_args();

    if let Some(raw) = &cli.lang {
        if parse_lang_value(raw).is_none() {
            eprintln!("{}", msg(lang, Msg::InvalidLang(raw.to_string())));
            std::process::exit(2);
        }
    }

    let mut display = DisplayConfig::from_flags(
        cli.bin,
        cli.oct,
        cli.all,
        cli.dec,
        cli.hex,
        cli.show_char,
        cli.oneline,
    );

    if cli.interactive || expression.is_empty() {
        if let Err(err) = run_repl(&mut display, lang) {
            eprintln!("{}", msg(lang, Msg::ReplError(err)));
            std::process::exit(2);
        }
        return;
    }

    let input = expression.join(" ");
    match try_handle_color_input(&input, &mut io::stdout(), lang) {
        Ok(Some(_)) => return,
        Ok(None) => {}
        Err(err) => {
            eprintln!("{}", msg(lang, Msg::ColorParseFailed(err)));
            std::process::exit(2);
        }
    }

    let ctx = EvalContext::default();
    let value = match eval_expression_with_env(&input, &ctx) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("{}", msg(lang, Msg::ParseFailed(err)));
            std::process::exit(2);
        }
    };

    print_value(value, &display, lang);
}

#[derive(Default)]
struct EvalContext {
    vars: HashMap<String, i128>,
    last: Option<i128>,
}

#[derive(Clone, Copy)]
struct DisplayConfig {
    show_dec: bool,
    show_hex: bool,
    show_bin: bool,
    show_oct: bool,
    show_char: bool,
    oneline: bool,
}

impl DisplayConfig {
    fn from_flags(
        bin: Option<bool>,
        oct: Option<bool>,
        all: bool,
        dec: Option<bool>,
        hex: Option<bool>,
        show_char: bool,
        oneline: bool,
    ) -> Self {
        let mut cfg = Self {
            show_dec: true,
            show_hex: true,
            show_bin: false,
            show_oct: false,
            show_char: false,
            oneline,
        };
        if all {
            cfg.show_dec = true;
            cfg.show_hex = true;
            cfg.show_bin = true;
            cfg.show_oct = true;
            cfg.show_char = true;
        }
        if let Some(value) = bin {
            cfg.show_bin = value;
        }
        if let Some(value) = oct {
            cfg.show_oct = value;
        }
        if show_char {
            cfg.show_char = true;
        }
        if let Some(value) = dec {
            cfg.show_dec = value;
        }
        if let Some(value) = hex {
            cfg.show_hex = value;
        }
        cfg
    }

    fn show_dec(&self) -> bool {
        self.show_dec
    }

    fn show_hex(&self) -> bool {
        self.show_hex
    }

    fn show_bin(&self) -> bool {
        self.show_bin
    }

    fn show_oct(&self) -> bool {
        self.show_oct
    }

    fn show_char(&self) -> bool {
        self.show_char
    }
}

fn split_args() -> (Cli, Vec<String>, Lang) {
    let args: Vec<String> = std::env::args().collect();
    let lang = resolve_lang(&args);
    if args.iter().any(|arg| is_help_flag(arg)) {
        print_help(lang);
        std::process::exit(0);
    }
    if args.iter().any(|arg| is_version_flag(arg)) {
        let cli = Cli::parse_from(&args);
        return (cli, Vec::new(), lang);
    }
    let mut flag_args = Vec::new();
    let mut expr_args = Vec::new();
    if let Some(first) = args.first() {
        flag_args.push(first.clone());
    }
    let mut iter = args.into_iter().skip(1);
    while let Some(arg) = iter.next() {
        if arg == "--" {
            expr_args.extend(iter);
            break;
        }
        if arg.starts_with("--lang=")
            || arg.starts_with("--dec=")
            || arg.starts_with("--hex=")
            || arg.starts_with("--bin=")
            || arg.starts_with("--oct=")
        {
            flag_args.push(arg);
            continue;
        }
        if arg == "--lang" {
            flag_args.push(arg);
            if let Some(value) = iter.next() {
                flag_args.push(value);
            }
            continue;
        }
        if is_flag(&arg) {
            let needs_value = needs_optional_value(&arg);
            flag_args.push(arg);
            if needs_value {
                if let Some(value) = iter.next() {
                    if is_toggle_value(&value) {
                        flag_args.push(value);
                        continue;
                    }
                    expr_args.push(value);
                }
            }
        } else {
            expr_args.push(arg);
        }
    }
    let cli = Cli::parse_from(flag_args);
    (cli, expr_args, lang)
}

fn is_flag(arg: &str) -> bool {
    matches!(
        arg,
        "-b" | "--bin"
            | "-o"
            | "--oct"
            | "-a"
            | "--all"
            | "--dec"
            | "--hex"
            | "-c"
            | "--char"
            | "-l"
            | "--oneline"
            | "-i"
            | "--interactive"
            | "--lang"
    )
}

fn is_help_flag(arg: &str) -> bool {
    matches!(arg, "-h" | "--help")
}

fn is_version_flag(arg: &str) -> bool {
    matches!(arg, "-V" | "--version")
}

fn needs_optional_value(arg: &str) -> bool {
    matches!(arg, "--dec" | "--hex" | "--bin" | "--oct" | "-b" | "-o")
}

fn is_toggle_value(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "1" | "0" | "on" | "off" | "true" | "false"
    )
}

fn parse_toggle_value(raw: &str) -> Result<bool, String> {
    match raw.to_ascii_lowercase().as_str() {
        "1" | "on" | "true" => Ok(true),
        "0" | "off" | "false" => Ok(false),
        _ => Err("expected 1/0/on/off/true/false".to_string()),
    }
}

fn resolve_lang(args: &[String]) -> Lang {
    if let Some(lang) = extract_lang_arg(args) {
        return lang;
    }
    detect_system_lang()
}

fn extract_lang_arg(args: &[String]) -> Option<Lang> {
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if let Some(value) = arg.strip_prefix("--lang=") {
            if let Some(lang) = parse_lang_value(value) {
                return Some(lang);
            }
        }
        if arg == "--lang" {
            if let Some(value) = iter.next() {
                if let Some(lang) = parse_lang_value(value) {
                    return Some(lang);
                }
            }
        }
    }
    None
}

fn parse_lang_value(value: &str) -> Option<Lang> {
    let lower = value.to_ascii_lowercase();
    match lower.as_str() {
        "en" => Some(Lang::En),
        "cn" | "zh" | "zh-cn" | "zh_cn" => Some(Lang::Zh),
        _ => None,
    }
}

fn detect_system_lang() -> Lang {
    #[cfg(windows)]
    if let Some(locale) = detect_windows_locale() {
        if is_zh_tag(&locale) {
            return Lang::Zh;
        }
    }
    let vars = ["LC_ALL", "LC_MESSAGES", "LANG"];
    for key in vars {
        if let Ok(value) = std::env::var(key) {
            if is_zh_tag(&value) {
                return Lang::Zh;
            }
        }
    }
    Lang::En
}

#[cfg(windows)]
fn detect_windows_locale() -> Option<String> {
    const LOCALE_NAME_MAX: usize = 85;
    let mut buffer = [0u16; LOCALE_NAME_MAX];
    let len = unsafe { GetUserDefaultLocaleName(&mut buffer) };
    if len <= 0 {
        return None;
    }
    let mut len = len as usize;
    if len > 0 && buffer[len - 1] == 0 {
        len -= 1;
    }
    Some(String::from_utf16_lossy(&buffer[..len]))
}

fn is_zh_tag(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("zh")
}

fn print_help(lang: Lang) {
    match lang {
        Lang::Zh => {
            println!("hex - 进制转换与基本运算工具");
            println!();
            println!("用法:");
            println!("  hex [FLAGS/OPTIONS] [EXPRESSION]");
            println!();
            println!("示例:");
            println!("  hex 0x15");
            println!("  hex 0x15+100");
            println!("  hex 0x1A or 0b100 --bin");
            println!("  hex \"0x50 & 0xFF\"");
            println!("  hex --dec 0 --bin 1010");
            println!("  hex --oneline 255");
            println!("  hex \"#FF5733\"");
            println!();
            println!("选项:");
            println!("  -b, --bin[=0|1]     显示/隐藏二进制");
            println!("  -o, --oct[=0|1]     显示/隐藏八进制");
            println!("  -a, --all           显示全部格式(Dec/Hex/Oct/Bin/Char)");
            println!("      --dec[=0|1]     显示/隐藏十进制");
            println!("      --hex[=0|1]     显示/隐藏十六进制");
            println!("  -c, --char          显示字符(单字节)");
            println!("  -l, --oneline       单行输出");
            println!("  -i, --interactive   进入交互模式");
            println!("      --lang <LANG>   语言: en/cn/zh/zh-CN");
            println!("  -h, --help          显示帮助");
            println!("  -V, --version       显示版本");
        }
        Lang::En => {
            println!("hex - base converter and calculator");
            println!();
            println!("Usage:");
            println!("  hex [FLAGS/OPTIONS] [EXPRESSION]");
            println!();
            println!("Examples:");
            println!("  hex 0x15");
            println!("  hex 0x15+100");
            println!("  hex 0x1A or 0b100 --bin");
            println!("  hex \"0x50 & 0xFF\"");
            println!("  hex --dec 0 --bin 1010");
            println!("  hex --oneline 255");
            println!("  hex \"#FF5733\"");
            println!();
            println!("Options:");
            println!("  -b, --bin[=0|1]     Show/Hide binary");
            println!("  -o, --oct[=0|1]     Show/Hide octal");
            println!("  -a, --all           Show all formats (Dec/Hex/Oct/Bin/Char)");
            println!("      --dec[=0|1]     Enable/disable decimal");
            println!("      --hex[=0|1]     Enable/disable hexadecimal");
            println!("  -c, --char          Show character (single byte)");
            println!("  -l, --oneline       Print in one line");
            println!("  -i, --interactive   Enter interactive mode");
            println!("      --lang <LANG>   Language: en/cn/zh/zh-CN");
            println!("  -h, --help          Show help");
            println!("  -V, --version       Show version");
        }
    }
}

fn print_repl_help(lang: Lang) {
    match lang {
        Lang::Zh => {
            println!("交互模式帮助:");
            println!("  输入表达式后回车进行计算");
            println!("  let a = 0xFF  定义变量");
            println!("  _ * 2         使用上一条结果");
            println!("  数字格式示例: 0xFF 0b1010 0o77 123h");
            println!("  :bin [on|off] 二进制显示开关");
            println!("  :oct [on|off] 八进制显示开关");
            println!("  :dec [on|off] 十进制显示开关");
            println!("  :hex [on|off] 十六进制显示开关");
            println!("  :char [on|off] 字符显示开关");
            println!("  :oneline [on|off] 单行输出开关");
            println!("  :all          显示全部格式");
            println!("  :vars         查看变量");
            println!("  :? 或 :help   显示帮助");
            println!("  :quit / :q    退出");
        }
        Lang::En => {
            println!("Interactive help:");
            println!("  Enter an expression to evaluate");
            println!("  let a = 0xFF  Define variable");
            println!("  _ * 2         Use previous result");
            println!("  Number formats: 0xFF 0b1010 0o77 123h");
            println!("  :bin [on|off] Toggle binary output");
            println!("  :oct [on|off] Toggle octal output");
            println!("  :dec [on|off] Toggle decimal output");
            println!("  :hex [on|off] Toggle hexadecimal output");
            println!("  :char [on|off] Toggle char output");
            println!("  :oneline [on|off] Toggle one-line output");
            println!("  :all          Show all formats");
            println!("  :vars         List variables");
            println!("  :? or :help   Show help");
            println!("  :quit / :q    Exit");
        }
    }
}

fn eval_expression_with_env(input: &str, ctx: &EvalContext) -> Result<i128, String> {
    let tokens = tokenize(input)?;
    let mut parser = ParserState {
        tokens,
        pos: 0,
        ctx,
    };
    let value = parser.parse_expr(1)?;
    if parser.pos != parser.tokens.len() {
        return Err("发现多余的内容".to_string());
    }
    Ok(value)
}

struct ParserState<'a> {
    tokens: Vec<Token>,
    pos: usize,
    ctx: &'a EvalContext,
}

impl ParserState<'_> {
    fn parse_expr(&mut self, min_prec: u8) -> Result<i128, String> {
        let mut lhs = self.parse_prefix()?;
        loop {
            let op = match self.peek_infix() {
                Some(op) => op,
                None => break,
            };
            let (prec, assoc_left) = infix_precedence(op);
            if prec < min_prec {
                break;
            }
            self.pos += 1;
            let next_min = if assoc_left { prec + 1 } else { prec };
            let rhs = self.parse_expr(next_min)?;
            lhs = apply_infix(op, lhs, rhs)?;
        }
        Ok(lhs)
    }

    fn parse_prefix(&mut self) -> Result<i128, String> {
        match self.next_token() {
            Some(Token::Op(op)) if is_prefix(op) => {
                let rhs = self.parse_expr(PREFIX_PREC)?;
                apply_prefix(op, rhs)
            }
            Some(Token::Number(n)) => Ok(n),
            Some(Token::Ident(name)) => self.resolve_ident(&name),
            Some(Token::LParen) => {
                let value = self.parse_expr(1)?;
                match self.next_token() {
                    Some(Token::RParen) => Ok(value),
                    _ => Err("缺少右括号".to_string()),
                }
            }
            Some(_) => Err("表达式语法错误".to_string()),
            None => Err("表达式为空".to_string()),
        }
    }

    fn peek_infix(&self) -> Option<Op> {
        match self.tokens.get(self.pos) {
            Some(Token::Op(op)) if is_infix(*op) => Some(*op),
            _ => None,
        }
    }

    fn next_token(&mut self) -> Option<Token> {
        let tok = self.tokens.get(self.pos).cloned();
        if tok.is_some() {
            self.pos += 1;
        }
        tok
    }

    fn resolve_ident(&self, name: &str) -> Result<i128, String> {
        if name == "_" {
            return self.ctx.last.ok_or_else(|| "尚无上一次结果".to_string());
        }
        self.ctx
            .vars
            .get(name)
            .copied()
            .ok_or_else(|| format!("未定义变量: {name}"))
    }
}

const PREFIX_PREC: u8 = 7;

fn is_prefix(op: Op) -> bool {
    matches!(op, Op::Add | Op::Sub | Op::Not)
}

fn is_infix(op: Op) -> bool {
    !matches!(op, Op::Not)
}

fn infix_precedence(op: Op) -> (u8, bool) {
    match op {
        Op::Mul | Op::Div => (6, true),
        Op::Add | Op::Sub => (5, true),
        Op::Shl | Op::Shr => (4, true),
        Op::And => (3, true),
        Op::Xor => (2, true),
        Op::Or => (1, true),
        Op::Not => (0, true),
    }
}

fn apply_prefix(op: Op, rhs: i128) -> Result<i128, String> {
    match op {
        Op::Add => Ok(rhs),
        Op::Sub => rhs.checked_neg().ok_or_else(|| "溢出".to_string()),
        Op::Not => Ok(!rhs),
        _ => Err("不支持的前缀运算符".to_string()),
    }
}

fn apply_infix(op: Op, lhs: i128, rhs: i128) -> Result<i128, String> {
    match op {
        Op::Add => lhs.checked_add(rhs).ok_or_else(|| "溢出".to_string()),
        Op::Sub => lhs.checked_sub(rhs).ok_or_else(|| "溢出".to_string()),
        Op::Mul => lhs.checked_mul(rhs).ok_or_else(|| "溢出".to_string()),
        Op::Div => {
            if rhs == 0 {
                return Err("除数不能为 0".to_string());
            }
            lhs.checked_div(rhs).ok_or_else(|| "溢出".to_string())
        }
        Op::And => Ok(lhs & rhs),
        Op::Or => Ok(lhs | rhs),
        Op::Xor => Ok(lhs ^ rhs),
        Op::Shl => shift_left(lhs, rhs),
        Op::Shr => shift_right(lhs, rhs),
        Op::Not => Err("不支持的中缀运算符".to_string()),
    }
}

fn shift_left(lhs: i128, rhs: i128) -> Result<i128, String> {
    if rhs < 0 {
        return Err("位移不能为负数".to_string());
    }
    let shift = u32::try_from(rhs).map_err(|_| "位移过大".to_string())?;
    lhs.checked_shl(shift).ok_or_else(|| "溢出".to_string())
}

fn shift_right(lhs: i128, rhs: i128) -> Result<i128, String> {
    if rhs < 0 {
        return Err("位移不能为负数".to_string());
    }
    let shift = u32::try_from(rhs).map_err(|_| "位移过大".to_string())?;
    lhs.checked_shr(shift).ok_or_else(|| "溢出".to_string())
}

fn tokenize(input: &str) -> Result<Vec<Token>, String> {
    let bytes = input.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        match b {
            b'(' => {
                tokens.push(Token::LParen);
                i += 1;
            }
            b')' => {
                tokens.push(Token::RParen);
                i += 1;
            }
            b'<' | b'>' => {
                if i + 1 >= bytes.len() || bytes[i + 1] != b {
                    return Err("位移运算符需要使用 << 或 >>".to_string());
                }
                let op = if b == b'<' { Op::Shl } else { Op::Shr };
                tokens.push(Token::Op(op));
                i += 2;
            }
            b'+' => {
                tokens.push(Token::Op(Op::Add));
                i += 1;
            }
            b'-' => {
                tokens.push(Token::Op(Op::Sub));
                i += 1;
            }
            b'*' => {
                tokens.push(Token::Op(Op::Mul));
                i += 1;
            }
            b'/' => {
                tokens.push(Token::Op(Op::Div));
                i += 1;
            }
            b'&' => {
                tokens.push(Token::Op(Op::And));
                i += 1;
            }
            b'|' => {
                tokens.push(Token::Op(Op::Or));
                i += 1;
            }
            b'^' => {
                tokens.push(Token::Op(Op::Xor));
                i += 1;
            }
            b'~' => {
                tokens.push(Token::Op(Op::Not));
                i += 1;
            }
            b'#' => {
                return Err("颜色输入暂未支持，请等待第二步".to_string());
            }
            b'0'..=b'9' => {
                let (token, next_i) = parse_number(bytes, i)?;
                tokens.push(Token::Number(token));
                i = next_i;
            }
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                let (word, next_i) = parse_word(bytes, i);
                if let Some(num) = parse_hex_suffix(&word)? {
                    tokens.push(Token::Number(num));
                    i = next_i;
                    continue;
                }
                let op = match word.as_str() {
                    "add" | "plus" => Op::Add,
                    "sub" | "minus" => Op::Sub,
                    "mul" | "x" => Op::Mul,
                    "div" => Op::Div,
                    "and" => Op::And,
                    "or" => Op::Or,
                    "xor" => Op::Xor,
                    "not" => Op::Not,
                    "shl" => Op::Shl,
                    "shr" => Op::Shr,
                    _ => {
                        tokens.push(Token::Ident(word));
                        i = next_i;
                        continue;
                    }
                };
                tokens.push(Token::Op(op));
                i = next_i;
            }
            _ => return Err(format!("无法识别的字符: {}", b as char)),
        }
    }
    Ok(tokens)
}

fn parse_word(bytes: &[u8], start: usize) -> (String, usize) {
    let mut i = start;
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
        i += 1;
    }
    (String::from_utf8_lossy(&bytes[start..i]).to_string(), i)
}

fn parse_hex_suffix(word: &str) -> Result<Option<i128>, String> {
    let mut chars = word.chars();
    let last = chars.next_back();
    if matches!(last, Some('h') | Some('H')) {
        let body: String = chars.collect();
        if body.is_empty() {
            return Err("非法的十六进制后缀".to_string());
        }
        if !body.chars().all(|c| c.is_ascii_hexdigit() || c == '_') {
            return Ok(None);
        }
        let value = parse_radix(&body, 16)?;
        return Ok(Some(value));
    }
    Ok(None)
}

fn parse_number(bytes: &[u8], start: usize) -> Result<(i128, usize), String> {
    if bytes[start] == b'0' && start + 1 < bytes.len() {
        let prefix = bytes[start + 1];
        if prefix == b'x' || prefix == b'X' {
            let (digits, next_i) = collect_digits(bytes, start + 2, 16)?;
            if digits.is_empty() {
                return Err("非法的十六进制".to_string());
            }
            return Ok((parse_radix(&digits, 16)?, next_i));
        }
        if prefix == b'b' || prefix == b'B' {
            let (digits, next_i) = collect_digits(bytes, start + 2, 2)?;
            if digits.is_empty() {
                return Err("非法的二进制".to_string());
            }
            return Ok((parse_radix(&digits, 2)?, next_i));
        }
        if prefix == b'o' || prefix == b'O' {
            let (digits, next_i) = collect_digits(bytes, start + 2, 8)?;
            if digits.is_empty() {
                return Err("非法的八进制".to_string());
            }
            return Ok((parse_radix(&digits, 8)?, next_i));
        }
    }

    let (digits, mut next_i) = collect_digits(bytes, start, 10)?;
    if digits.is_empty() {
        return Err("非法的十进制".to_string());
    }
    if next_i < bytes.len() && (bytes[next_i] == b'h' || bytes[next_i] == b'H') {
        next_i += 1;
        return Ok((parse_radix(&digits, 16)?, next_i));
    }
    Ok((parse_decimal(&digits)?, next_i))
}

fn collect_digits(bytes: &[u8], start: usize, base: u32) -> Result<(String, usize), String> {
    let mut i = start;
    let mut out = String::new();
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == '_' {
            i += 1;
            continue;
        }
        let ok = match base {
            2 => c == '0' || c == '1',
            8 => c.is_ascii_digit() && c <= '7',
            10 => c.is_ascii_digit(),
            16 => c.is_ascii_hexdigit(),
            _ => false,
        };
        if !ok {
            break;
        }
        out.push(c);
        i += 1;
    }
    Ok((out, i))
}

fn parse_decimal(digits: &str) -> Result<i128, String> {
    let cleaned: String = digits.chars().filter(|c| *c != '_').collect();
    cleaned
        .parse::<i128>()
        .map_err(|_| format!("非法数字: {digits}"))
}

fn parse_radix(digits: &str, base: u32) -> Result<i128, String> {
    let cleaned: String = digits.chars().filter(|c| *c != '_').collect();
    i128::from_str_radix(&cleaned, base).map_err(|_| format!("非法数字: {digits}"))
}

fn format_hex(value: i128) -> String {
    let abs = value.unsigned_abs();
    let s = format!("0x{:X}", abs);
    if value < 0 { format!("-{s}") } else { s }
}

fn format_oct(value: i128) -> String {
    let abs = value.unsigned_abs();
    let s = format!("0o{:o}", abs);
    if value < 0 { format!("-{s}") } else { s }
}

fn format_bin(value: i128) -> String {
    let abs = value.unsigned_abs();
    let s = format!("{:b}", abs);
    if value < 0 { format!("-{s}") } else { s }
}

fn format_char(value: i128) -> Option<char> {
    if value < 0 || value > 255 {
        return None;
    }
    let ch = value as u8 as char;
    if ch.is_control() {
        return None;
    }
    Some(ch)
}

fn run_repl(display: &mut DisplayConfig, lang: Lang) -> Result<(), String> {
    let mut rl =
        DefaultEditor::new().map_err(|e| msg(lang, Msg::ReplStartFailed(e.to_string())))?;
    let mut ctx = EvalContext::default();
    print_repl_help(lang);
    loop {
        let line = rl.readline("hex > ");
        match line {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                rl.add_history_entry(line)
                    .map_err(|e| msg(lang, Msg::NoHistory(e.to_string())))?;
                match handle_repl_command(line, display, &ctx, lang) {
                    Ok(true) => continue,
                    Ok(false) => {}
                    Err(err) => {
                        eprintln!("{err}");
                        continue;
                    }
                }
                match try_handle_color_input(line, &mut io::stdout(), lang) {
                    Ok(Some(dec)) => {
                        ctx.last = Some(dec as i128);
                        continue;
                    }
                    Ok(None) => {}
                    Err(err) => {
                        eprintln!("{}", msg(lang, Msg::ColorParseFailed(err)));
                        continue;
                    }
                }
                match parse_assignment(line, lang) {
                    Ok(Some((name, expr))) => {
                        let value = match eval_expression_with_env(expr, &ctx) {
                            Ok(value) => value,
                            Err(err) => {
                                eprintln!("{}", msg(lang, Msg::ParseFailed(err)));
                                continue;
                            }
                        };
                        ctx.vars.insert(name, value);
                        ctx.last = Some(value);
                        print_value(value, display, lang);
                        continue;
                    }
                    Ok(None) => {}
                    Err(err) => {
                        eprintln!("{err}");
                        continue;
                    }
                }
                let value = match eval_expression_with_env(line, &ctx) {
                    Ok(value) => value,
                    Err(err) => {
                        eprintln!("{}", msg(lang, Msg::ParseFailed(err)));
                        continue;
                    }
                };
                ctx.last = Some(value);
                print_value(value, display, lang);
            }
            Err(ReadlineError::Interrupted) => {
                println!("{}", msg(lang, Msg::Cancelled));
            }
            Err(ReadlineError::Eof) => {
                println!("{}", msg(lang, Msg::Bye));
                break;
            }
            Err(err) => return Err(msg(lang, Msg::ReplError(err.to_string()))),
        }
    }
    Ok(())
}

fn handle_repl_command(
    line: &str,
    display: &mut DisplayConfig,
    ctx: &EvalContext,
    lang: Lang,
) -> Result<bool, String> {
    if !line.starts_with(':') {
        return Ok(false);
    }
    let parts: Vec<&str> = line.split_whitespace().collect();
    let cmd = parts[0];
    let arg = parts.get(1).copied();
    if parts.len() > 2 {
        return Err(match lang {
            Lang::Zh => "参数过多".to_string(),
            Lang::En => "Too many arguments".to_string(),
        });
    }
    match cmd {
        ":bin" => {
            apply_toggle(&mut display.show_bin, arg, lang)?;
        }
        ":oct" => {
            apply_toggle(&mut display.show_oct, arg, lang)?;
        }
        ":dec" => {
            apply_toggle(&mut display.show_dec, arg, lang)?;
        }
        ":hex" => {
            apply_toggle(&mut display.show_hex, arg, lang)?;
        }
        ":char" => {
            apply_toggle(&mut display.show_char, arg, lang)?;
        }
        ":oneline" => {
            apply_toggle(&mut display.oneline, arg, lang)?;
        }
        ":all" => {
            display.show_dec = true;
            display.show_hex = true;
            display.show_bin = true;
            display.show_oct = true;
            display.show_char = true;
            match lang {
                Lang::Zh => println!("已开启全部显示"),
                Lang::En => println!("All formats enabled"),
            }
        }
        ":vars" => {
            print_vars(ctx, lang);
        }
        ":help" | ":?" => {
            print_repl_help(lang);
        }
        ":quit" | ":exit" | ":q" => {
            println!("{}", msg(lang, Msg::Bye));
            std::process::exit(0);
        }
        _ => return Err(msg(lang, Msg::UnknownCommand(cmd.to_string()))),
    }
    Ok(true)
}

fn apply_toggle(flag: &mut bool, arg: Option<&str>, lang: Lang) -> Result<(), String> {
    if let Some(value) = arg {
        let enabled = match value.to_ascii_lowercase().as_str() {
            "on" | "1" | "true" => true,
            "off" | "0" | "false" => false,
            _ => {
                return Err(match lang {
                    Lang::Zh => "参数应为 on/off 或 1/0".to_string(),
                    Lang::En => "Argument should be on/off or 1/0".to_string(),
                });
            }
        };
        *flag = enabled;
    } else {
        *flag = !*flag;
    }
    print_toggle_state(*flag, lang);
    Ok(())
}

fn print_toggle_state(enabled: bool, lang: Lang) {
    let state = match (enabled, lang) {
        (true, Lang::Zh) => "开启",
        (false, Lang::Zh) => "关闭",
        (true, Lang::En) => "on",
        (false, Lang::En) => "off",
    };
    match lang {
        Lang::Zh => println!("已切换为: {state}"),
        Lang::En => println!("Toggled: {state}"),
    }
}

fn print_vars(ctx: &EvalContext, lang: Lang) {
    if ctx.vars.is_empty() {
        match lang {
            Lang::Zh => println!("当前没有变量"),
            Lang::En => println!("No variables"),
        }
        return;
    }
    let mut items: Vec<(&String, &i128)> = ctx.vars.iter().collect();
    items.sort_by(|a, b| a.0.cmp(b.0));
    match lang {
        Lang::Zh => println!("变量列表:"),
        Lang::En => println!("Variables:"),
    }
    for (name, value) in items {
        println!("  {name} = {value}");
    }
}

fn parse_assignment(line: &str, lang: Lang) -> Result<Option<(String, &str)>, String> {
    let trimmed = line.trim_start();
    if !trimmed.starts_with("let ") {
        return Ok(None);
    }
    let rest = trimmed[4..].trim_start();
    let (name, expr) = rest.split_once('=').ok_or_else(|| match lang {
        Lang::Zh => "变量赋值格式应为: let name = expr".to_string(),
        Lang::En => "Assignment format: let name = expr".to_string(),
    })?;
    let name = name.trim();
    let expr = expr.trim();
    if name.is_empty() || expr.is_empty() {
        return Err(match lang {
            Lang::Zh => "变量赋值格式应为: let name = expr".to_string(),
            Lang::En => "Assignment format: let name = expr".to_string(),
        });
    }
    if name == "_" {
        return Err(match lang {
            Lang::Zh => "变量名不能为 '_'".to_string(),
            Lang::En => "Variable name cannot be '_'".to_string(),
        });
    }
    if !is_valid_ident(name) {
        return Err(match lang {
            Lang::Zh => format!("非法变量名: {name}"),
            Lang::En => format!("Invalid variable name: {name}"),
        });
    }
    Ok(Some((name.to_string(), expr)))
}

fn is_valid_ident(name: &str) -> bool {
    let mut chars = name.chars();
    let first = match chars.next() {
        Some(c) => c,
        None => return false,
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn print_value(value: i128, display: &DisplayConfig, lang: Lang) {
    let mut parts = Vec::new();
    if display.show_dec() {
        parts.push(format!("Dec: {value}"));
    }
    if display.show_hex() {
        parts.push(format!("Hex: {}", format_hex(value)));
    }
    if display.show_oct() {
        parts.push(format!("Oct: {}", format_oct(value)));
    }
    if display.show_bin() {
        parts.push(format!("Bin: {}", format_bin(value)));
    }
    if display.show_char() {
        if let Some(ch) = format_char(value) {
            parts.push(format!("Char: {ch}"));
        }
    }
    if parts.is_empty() {
        println!("{}", msg(lang, Msg::NoOutput));
        return;
    }
    if display.oneline {
        println!("{}", parts.join(" "));
        return;
    }
    for part in parts {
        println!("{part}");
    }
}

fn try_handle_color_input(
    input: &str,
    out: &mut io::Stdout,
    lang: Lang,
) -> Result<Option<u32>, String> {
    let trimmed = input.trim();
    let info = match parse_color_input(trimmed, lang)? {
        Some(info) => info,
        None => return Ok(None),
    };
    print_color_info(trimmed, &info, out, lang).map_err(|e| e.to_string())?;
    Ok(Some(info.dec))
}

struct ColorInfo {
    r: u8,
    g: u8,
    b: u8,
    dec: u32,
    hex: String,
}

fn parse_color_input(input: &str, lang: Lang) -> Result<Option<ColorInfo>, String> {
    if !input.starts_with('#') {
        return Ok(None);
    }
    let hex = &input[1..];
    let (r, g, b) = match hex.len() {
        3 => {
            let r = parse_hex_byte(&hex[0..1], lang)?;
            let g = parse_hex_byte(&hex[1..2], lang)?;
            let b = parse_hex_byte(&hex[2..3], lang)?;
            (r * 17, g * 17, b * 17)
        }
        6 => {
            let r = parse_hex_byte(&hex[0..2], lang)?;
            let g = parse_hex_byte(&hex[2..4], lang)?;
            let b = parse_hex_byte(&hex[4..6], lang)?;
            (r, g, b)
        }
        _ => {
            return Err(match lang {
                Lang::Zh => "颜色长度必须为 #RGB 或 #RRGGBB".to_string(),
                Lang::En => "Color length must be #RGB or #RRGGBB".to_string(),
            });
        }
    };
    let dec = ((r as u32) << 16) | ((g as u32) << 8) | (b as u32);
    let hex = format!("#{:02X}{:02X}{:02X}", r, g, b);
    Ok(Some(ColorInfo { r, g, b, dec, hex }))
}

fn parse_hex_byte(s: &str, lang: Lang) -> Result<u8, String> {
    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(match lang {
            Lang::Zh => "颜色中包含非法字符".to_string(),
            Lang::En => "Invalid hex digits".to_string(),
        });
    }
    u8::from_str_radix(s, 16).map_err(|_| match lang {
        Lang::Zh => "颜色解析失败".to_string(),
        Lang::En => "Color parse failed".to_string(),
    })
}

fn print_color_info(
    input: &str,
    info: &ColorInfo,
    out: &mut io::Stdout,
    lang: Lang,
) -> io::Result<()> {
    let (h, s, l) = rgb_to_hsl(info.r, info.g, info.b);
    match lang {
        Lang::Zh => println!("输入: {input} (颜色)"),
        Lang::En => println!("Input: {input} (Color)"),
    }
    println!("----------------------");
    match lang {
        Lang::Zh => print!("预览: "),
        Lang::En => print!("Preview: "),
    }
    print_color_preview(info.r, info.g, info.b, out)?;
    println!();
    println!("RGB    : {}, {}, {}", info.r, info.g, info.b);
    println!("HSL    : {}, {}%, {}%", h, s, l);
    println!("Hex    : {}", info.hex);
    println!("Dec    : {}", info.dec);
    Ok(())
}

fn print_color_preview(r: u8, g: u8, b: u8, out: &mut io::Stdout) -> io::Result<()> {
    execute!(
        out,
        SetBackgroundColor(Color::Rgb { r, g, b }),
        Print("        "),
        ResetColor
    )?;
    out.flush()?;
    Ok(())
}

fn rgb_to_hsl(r: u8, g: u8, b: u8) -> (u16, u8, u8) {
    let rf = r as f64 / 255.0;
    let gf = g as f64 / 255.0;
    let bf = b as f64 / 255.0;
    let max = rf.max(gf.max(bf));
    let min = rf.min(gf.min(bf));
    let l = (max + min) / 2.0;
    if (max - min).abs() < f64::EPSILON {
        return (0, 0, (l * 100.0).round() as u8);
    }
    let d = max - min;
    let s = if l > 0.5 {
        d / (2.0 - max - min)
    } else {
        d / (max + min)
    };
    let mut h = if (max - rf).abs() < f64::EPSILON {
        (gf - bf) / d + if gf < bf { 6.0 } else { 0.0 }
    } else if (max - gf).abs() < f64::EPSILON {
        (bf - rf) / d + 2.0
    } else {
        (rf - gf) / d + 4.0
    };
    h /= 6.0;
    let h_deg = (h * 360.0).round() as u16;
    let s_pct = (s * 100.0).round() as u8;
    let l_pct = (l * 100.0).round() as u8;
    (h_deg, s_pct, l_pct)
}
