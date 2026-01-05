# hex

A fast, cross-platform base converter and expression calculator written in Rust.

## Features

- Smart base parsing: `0x` hex, `0b` binary, `0o` octal, `h` suffix hex
- Expression evaluation with operators and aliases (`and`, `or`, `xor`, `shl`, `shr`, `x`)
- Color input `#RGB` / `#RRGGBB` with preview
- Interactive REPL with variables and history
- Output format toggles and one-line mode
- Bilingual messages (auto-detect, `--lang` override)

## Install

```bash
cargo build --release
```

Binary will be in `target/release/hex` (or `hex.exe` on Windows).

## Usage

```bash
hex [FLAGS/OPTIONS] [EXPRESSION]
```

### Examples

```bash
hex 0x15
hex 0x15+100
hex 0x1A or 0b100 --bin
hex "0x50 & 0xFF"
hex --dec 0 --bin 1010
hex --oneline 255
hex "#FF5733"
```

### Options

- `-b, --bin[=0|1]` show/hide binary
- `-o, --oct[=0|1]` show/hide octal
- `-a, --all` show all formats (Dec/Hex/Oct/Bin/Char)
- `--dec[=0|1]` show/hide decimal
- `--hex[=0|1]` show/hide hexadecimal
- `-c, --char` show character (single byte)
- `-l, --oneline` print in one line
- `-i, --interactive` enter REPL
- `--lang <LANG>` `en/cn/zh/zh-CN`
- `-h, --help` help
- `-V, --version` version

## REPL

Start by running `hex` or `hex -i`.

Commands:

- `:bin [on|off]`, `:oct [on|off]`, `:dec [on|off]`, `:hex [on|off]`, `:char [on|off]`
- `:oneline [on|off]`
- `:all`
- `:vars`
- `:?` / `:help`
- `:quit` / `:q`

Examples:

```
hex > let a = 0xFF
hex > a + 1
hex > _ * 2
```

## License

MIT. See [LICENSE](LICENSE).
