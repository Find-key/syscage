# syscage
`syscage` 是一个使用 Rust 编写的 Linux 安全分析工具，当前提供两个子命令：
- `checksec`：检查 ELF 二进制的安全加固状态
- `checkbox`：执行目标程序并跟踪其安装的 seccomp 过滤器

它适合用于二进制安全分析、沙箱审计、CTF/Pwn 学习和 Linux 安全研究等场景。
## 功能

### `checksec`
分析 ELF 文件的常见安全属性，包括：
- `Arch`
- `RELRO`
- `SHSTK`
- `IBT`
- `Canary`
- `NX`
- `PIE`
- `FORTIFY`
- `RPATH`
- `RUNPATH`
- `Stripped`
- `RWX`
输出结果带有颜色高亮，方便快速识别风险项。

### `checkbox`
运行指定程序，并在它安装 seccomp 过滤器时进行跟踪与解析，支持识别：
- `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)`
- `seccomp(SECCOMP_SET_MODE_FILTER, ...)`
工具会尝试读取目标进程中的 seccomp BPF 程序，并输出带注释的规则列表，便于理解过滤器的行为。

## 项目结构
```/dev/null/syscage-tree.txt#L1-18
syscage/
├─ Cargo.toml
├─ Cargo.lock
├─ src/
│  ├─ main.rs
│  ├─ cli.rs
│  ├─ checksec/
│  │  ├─ mod.rs
│  │  ├─ format.rs
│  │  ├─ model.rs
│  │  └─ parser.rs
│  └─ seccomp/
│     ├─ mod.rs
│     ├─ bpf.rs
│     ├─ format.rs
│     └─ reader.rs
├─ tests/
├─ test/
└─ README.md
```

## 环境要求
- Rust
- Cargo
- Linux

其中 `checkbox` 依赖 `ptrace`，因此需要在支持 `ptrace` 的 Linux 环境中运行。某些系统可能还需要调整相关安全限制。

## 构建
```sh
cargo build
cargo build --release
```

## 使用方法
查看帮助：
```sh
cargo run -- --help
./target/debug/syscage --help
```

### 检查 ELF 安全属性
```sh
cargo run -- checksec /bin/ls
./target/debug/syscage checksec /bin/ls
```

示例输出：
```sh
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

### 跟踪 seccomp 过滤器
```sh
cargo run -- checkbox /path/to/program -- arg1 arg2
./target/debug/syscage checkbox /path/to/program -- arg1 arg2
```

当目标程序调用 seccomp 相关接口安装过滤器时，工具会打印：
- 过滤器安装来源
- seccomp flags
- BPF 指令列表
- 每条规则的可读注释
- seccomp 返回动作

## 命令行
当前支持以下命令：
```sh
syscage checksec <elf>
syscage checkbox <binary> [args...]
```

## 实现说明
### `checksec`
`checksec` 基于 ELF 解析结果识别安全属性，主要使用：
- ELF Header
- Program Header
- 动态节
- 符号表
- GNU Property Notes

### `checkbox`
`checkbox` 的基本流程是：
1. `fork` 子进程
2. 子进程执行目标程序
3. 父进程通过 `ptrace` 跟踪系统调用
4. 在 seccomp 过滤器安装时读取 `sock_fprog`
5. 解析并格式化 seccomp BPF 规则

## 测试
运行测试：
```sh
cargo test
cargo test -- --nocapture
```

## 注意事项
- `checksec` 面向 ELF 文件，非 ELF 输入会报错
- `checkbox` 依赖 Linux `ptrace`
- seccomp 过滤器的行为与内核版本、架构和目标程序实现有关
- `SHSTK` 和 `IBT` 仅对特定架构有意义

## 后续方向
这个项目后续可以继续扩展，例如：
- 增加 JSON 输出
- 支持批量扫描
- 支持目录递归分析
- 增强 seccomp 规则可视化
- 增加更多集成测试样本

## 贡献
欢迎提交 Issue 和 Pull Request。