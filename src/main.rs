use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "hex", version, about = "进制转换与基本运算工具")]
struct Cli {
    #[arg(short = 'b', long = "bin", help = "显示二进制")]
    bin: bool,

    #[arg(short = 'o', long = "oct", help = "显示八进制")]
    oct: bool,

    #[arg(short = 'a', long = "all", help = "显示全部格式(Dec/Hex/Oct/Bin)")]
    all: bool,

    #[arg(long = "no-copy", help = "禁用自动复制(暂未实现)")]
    no_copy: bool,

    #[arg(short = 'i', long = "interactive", help = "交互模式(暂未实现)")]
    interactive: bool,

    #[arg(value_name = "EXPR", trailing_var_arg = true)]
    expression: Vec<String>,
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

#[derive(Clone, Copy, Debug)]
enum Token {
    Number(i128),
    Op(Op),
    LParen,
    RParen,
}

fn main() {
    let cli = Cli::parse();
    let _ = cli.no_copy;

    if cli.interactive || cli.expression.is_empty() {
        eprintln!("交互模式尚未实现，请提供表达式参数。");
        std::process::exit(2);
    }

    let input = cli.expression.join(" ");
    let value = match eval_expression(&input) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("解析失败: {err}");
            std::process::exit(2);
        }
    };

    let show_bin = cli.bin || cli.all;
    let show_oct = cli.oct || cli.all;

    println!("Dec: {value}");
    println!("Hex: {}", format_hex(value));
    if show_oct {
        println!("Oct: {}", format_oct(value));
    }
    if show_bin {
        println!("Bin: {}", format_bin(value));
    }
}

fn eval_expression(input: &str) -> Result<i128, String> {
    let tokens = tokenize(input)?;
    let mut parser = ParserState { tokens, pos: 0 };
    let value = parser.parse_expr(1)?;
    if parser.pos != parser.tokens.len() {
        return Err("发现多余的内容".to_string());
    }
    Ok(value)
}

struct ParserState {
    tokens: Vec<Token>,
    pos: usize,
}

impl ParserState {
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
                    _ => return Err(format!("未知标识符: {word}")),
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
