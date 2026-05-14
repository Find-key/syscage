# syscage

Linux 安全分析工具，使用 Rust 编写，适用于二进制安全分析、沙箱审计、CTF/Pwn 学习和 Linux 安全研究等场景。

## 功能

### `checksec` — 检查 ELF 安全加固

分析 ELF 文件的 12 项安全属性：

`Arch` `RELRO` `SHSTK` `IBT` `Canary` `NX` `PIE` `FORTIFY` `RPATH` `RUNPATH` `Stripped` `RWX`

输出带 ANSI 颜色高亮：绿色 = 安全，红色 = 风险，黄色 = 未知。

### `checkbox` — 跟踪 seccomp 过滤器

运行目标程序，通过 `ptrace` 捕获 seccomp 安装调用（`prctl(PR_SET_SECCOMP)` 和 `seccomp(SECCOMP_SET_MODE_FILTER)`），读取并解析 seccomp BPF 程序，输出带注释的规则列表。

## 环境要求

- Rust + Cargo
- Linux（`checkbox` 依赖 `ptrace`，某些系统可能需要调整 `ptrace` 安全限制）

## 构建

```sh
cargo build --release
```

## 使用方法

```sh
# 查看帮助
syscage --help

# 检查 ELF 安全属性
syscage checksec <elf>

# 跟踪 seccomp 过滤器
syscage checkbox <binary> [-- <args>]
```

### `checksec` 示例

```sh
$ syscage checksec /bin/ls
File: /bin/ls
Arch:          amd64-64-little
RELRO:         Full RELRO
SHSTK:         Enabled
IBT:           Enabled
Canary:        Enabled
NX:            Enabled
PIE:           Enabled
FORTIFY:       Enabled
RPATH:         Disabled
RUNPATH:       Disabled
Stripped:      Disabled
RWX:           Disabled
```

### `checkbox` 示例

```sh
$ syscage checkbox /path/to/program -- arg1 arg2
[*] Executing: /path/to/program
[*] With args: ["arg1", "arg2"]
Monitoring child process PID: 12345

=== Seccomp filter detected ===
Source: seccomp(SECCOMP_SET_MODE_FILTER, flags=0x5 [TSYNC, LOG])

 line  CODE  JT   JF      K           COMMENT
==============================================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x01 0xc000003e  if (A != ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0003: 0x06 0x00 0x00 0x00000000  return KILL
Status: loaded
```

输出包括：过滤器安装来源、seccomp flags、BPF 指令列表及可读注释、seccomp 返回动作。

## 实现说明

### `checksec`

`checksec` 基于 ELF 解析结果识别安全属性，主要使用：

- ELF Header
- Program Header
- 动态节
- 符号表
- GNU Property Notes

### `checkbox`

`checkbox` 的基本流程：

1. `fork` 子进程并执行目标程序
2. 父进程通过 `ptrace` 跟踪系统调用
3. 在 seccomp 过滤器安装时读取 `sock_fprog` 结构
4. 解析并格式化 seccomp BPF 规则

## 测试

```sh
cargo test
```

## 注意事项

- `checksec` 仅支持 ELF 文件，非 ELF 输入会报错
- `checkbox` 依赖 Linux `ptrace`，部分系统需调整 `kernel.yama.ptrace_scope`
- seccomp 过滤器行为与内核版本、架构和目标程序实现有关
- `SHSTK` 和 `IBT` 仅对 x86 有意义，其他架构显示 Unknown

## 后续方向

- 增加 JSON 输出
- 支持批量扫描与目录递归分析
- 增强 seccomp 规则可视化
- 增加更多集成测试样本

## 贡献

欢迎提交 Issue 和 Pull Request。
