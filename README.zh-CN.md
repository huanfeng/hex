# hex

一个用 Rust 编写的快速、跨平台进制转换与表达式计算工具。

## 特性

- 智能进制识别：`0x` 十六进制、`0b` 二进制、`0o` 八进制、`h` 后缀十六进制
- 表达式计算与运算符别名（`and`/`or`/`xor`/`shl`/`shr`/`x`）
- 颜色输入 `#RGB` / `#RRGGBB` 预览
- 交互式 REPL，支持变量与历史
- 输出格式开关与单行输出
- 中英文提示（自动检测，可用 `--lang` 覆盖）

## 安装

```bash
cargo build --release
```

二进制位于 `target/release/hex`（Windows 为 `hex.exe`）。

## 用法

```bash
hex [FLAGS/OPTIONS] [EXPRESSION]
```

### 示例

```bash
hex 0x15
hex 0x15+100
hex 0x1A or 0b100 --bin
hex "0x50 & 0xFF"
hex --dec 0 --bin 1010
hex --oneline 255
hex "#FF5733"
```

### 选项

- `-b, --bin[=0|1]` 显示/隐藏二进制
- `-o, --oct[=0|1]` 显示/隐藏八进制
- `-a, --all` 显示全部格式（Dec/Hex/Oct/Bin/Char）
- `--dec[=0|1]` 显示/隐藏十进制
- `--hex[=0|1]` 显示/隐藏十六进制
- `-c, --char` 显示字符（单字节）
- `-l, --oneline` 单行输出
- `-i, --interactive` 进入 REPL
- `--lang <LANG>` `en/cn/zh/zh-CN`
- `-h, --help` 帮助
- `-V, --version` 版本

## REPL

运行 `hex` 或 `hex -i` 进入。

指令：

- `:bin [on|off]`, `:oct [on|off]`, `:dec [on|off]`, `:hex [on|off]`, `:char [on|off]`
- `:oneline [on|off]`
- `:all`
- `:vars`
- `:?` / `:help`
- `:quit` / `:q`

示例：

```
hex > let a = 0xFF
hex > a + 1
hex > _ * 2
```

## License

MIT，详见 [LICENSE](LICENSE)。
