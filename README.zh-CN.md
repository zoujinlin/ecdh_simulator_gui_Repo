# ECDH 密钥交换模拟器 GUI

[English README](./README.md)

这是一个基于 Python + tkinter 的桌面图形界面工具，用于演示和验证多种椭圆曲线下的 ECDH（Elliptic Curve Diffie-Hellman）密钥交换过程。

## 项目简介

本项目通过直观的图形界面，模拟 Host 与 Device 两端的 ECDH 密钥协商流程。你可以在界面中生成、导入和比对双方的私钥/公钥，查看共享密钥结果，并基于 HKDF-SHA256 进一步派生会话密钥。

它适合以下场景：

- 学习 ECDH 协议流程
- 调试 ECC/ECDH 相关实现
- 验证十六进制密钥材料的导入与转换
- 与 MCU/嵌入式设备做联调比对

## 功能说明

- 支持多种标准椭圆曲线：
  - SECP256R1（NIST P-256）
  - SECP384R1（NIST P-384）
  - SECP521R1（NIST P-521）
  - SECP224R1（NIST P-224）
  - SECP256K1（默认）
- 可分别为 Host 和 Device 生成私钥/公钥对
- 支持导入两种格式的密钥数据：
  - 标准十六进制格式，例如 `0x1234abcd`
  - C 数组风格十六进制格式，例如 `0x12 0x34 0xab 0xcd`
- 执行 ECDH 密钥交换并校验双方共享密钥是否一致
- 使用 HKDF-SHA256 从共享密钥派生会话密钥
- 可选显示完整共享点 `X||Y`，便于 MCU / 嵌入式场景校验
- 同屏展示 Host 与 Device 的输出结果，便于对比分析

## 环境要求

- 建议使用 Python 3.9 及以上版本
- Python 依赖：[`cryptography`](https://pypi.org/project/cryptography/)
- 需要可用的 `tkinter` 图形界面运行环境

> 在 Windows 官方 Python 安装包以及部分 macOS Python 环境中，`tkinter` 通常已内置。  
> 在 Linux 环境下，可能需要额外安装，例如 Debian/Ubuntu 常见为 `python3-tk`。

## 安装步骤

1. 克隆仓库：

   ```bash
   git clone https://github.com/zoujinlin/ecdh_simulator_gui_Repo.git
   cd ecdh_simulator_gui_Repo
   ```

2. 安装 Python 依赖：

   ```bash
   pip install cryptography
   ```

3. 确认当前 Python 环境已具备 `tkinter` 支持。

## 运行方式

在仓库根目录执行：

```bash
python ecdh_simulator_gui.py
```

## 使用示例

1. 启动程序。
2. 在下拉框中选择目标椭圆曲线。
3. 点击 **Generate Host Key Pair** 与 **Generate Device Key Pair** 生成双方密钥对。
4. 如有需要，可手动替换为自己的标准十六进制或 C 数组风格十六进制密钥数据。
5. 点击 **Perform Key Exchange & Verify** 执行密钥交换。
6. 查看以下结果：
   - Host 侧共享密钥输出
   - Device 侧共享密钥输出
   - HKDF 派生的会话密钥
   - 双方共享密钥是否一致的校验结果
7. 如需与嵌入式侧做更细粒度对比，可勾选 **Show shared point X||Y (MCU verification)** 查看完整共享点坐标。

### 支持的密钥输入格式

标准十六进制格式：

```text
0x11223344aabbccdd
```

C 数组风格十六进制格式：

```text
0x11 0x22 0x33 0x44 0xaa 0xbb 0xcc 0xdd
```

## 项目结构

```text
ecdh_simulator_gui_Repo/
├── ecdh_simulator_gui.py   # tkinter 图形界面主程序
├── README.md               # 英文说明文档
├── README.zh-CN.md         # 中文说明文档
└── LICENSE                 # MIT 许可证
```

## 注意事项 / 免责声明

- 本项目主要用于学习、演示、联调与兼容性验证，不应直接视为生产级安全方案说明。
- 界面中显示的密钥与共享结果仅适合本地测试，请勿将演示或暴露过的密钥材料直接用于真实生产环境。
- 切换曲线后，请重新生成 Host 和 Device 两端的密钥对，再执行密钥交换。
- 该程序依赖图形界面环境；在无桌面的服务器或纯命令行环境中通常无法直接启动。

## 许可证

本项目采用 [MIT License](./LICENSE) 开源许可。
