# ECDH Key Exchange Simulator GUI

一个基于 Python/Tkinter 的 ECDH 密钥交换可视化仿真工具，支持多条常见椭圆曲线、Host/Device 双端密钥生成、手动密钥导入、共享密钥计算、HKDF 会话密钥派生，以及面向 MCU/嵌入式调试的十六进制与 C 数组格式输出。

A Python/Tkinter GUI for simulating Elliptic Curve Diffie-Hellman (ECDH) key exchange. It supports multiple standard elliptic curves, Host/Device key generation, manual key import, shared-secret calculation, HKDF session-key derivation, and hex/C-array output formats useful for MCU and embedded verification.

## 项目特性 / Features

- 多曲线支持：`SECP256K1`、`SECP256R1 (NIST P-256)`、`SECP384R1 (NIST P-384)`、`SECP521R1 (NIST P-521)`、`SECP224R1 (NIST P-224)`。
- Host/Device 双端建模：分别生成、输入、校验 Host 与 Device 的私钥和公钥。
- 双格式输入输出：支持标准十六进制格式（如 `0x...`）和 C 数组字节格式（如 `0x12 0x34 ...`）。
- 公钥派生：可由私钥生成对应公钥，公钥采用未压缩点的 `X || Y` 字节内容，不包含 `0x04` 前缀。
- ECDH 交换验证：分别从 Host 和 Device 视角计算共享密钥，并验证两端 X 坐标是否一致。
- HKDF 派生会话密钥：使用 `HKDF-SHA256` 从 ECDH shared secret 派生 32 字节 session key。
- 可选共享点输出：勾选 `Show shared point X||Y (MCU verification)` 后输出共享点完整 `X || Y`，便于和 MCU/固件侧实现对比。
- 图形界面：使用 Python 标准库 `tkinter` 构建，无需浏览器或 Web 服务。

---

- Multi-curve support: `SECP256K1`, `SECP256R1 (NIST P-256)`, `SECP384R1 (NIST P-384)`, `SECP521R1 (NIST P-521)`, and `SECP224R1 (NIST P-224)`.
- Host/Device workflow: generate, enter, and validate private/public keys for both parties.
- Dual input/output formats: standard hex (`0x...`) and C-array byte format (`0x12 0x34 ...`).
- Public-key derivation: derive a public key from a private key. Public keys are displayed as uncompressed point `X || Y` bytes without the `0x04` prefix.
- ECDH verification: calculate the shared secret from both Host and Device perspectives and verify that the X coordinate matches.
- HKDF session key derivation: derive a 32-byte session key from the ECDH shared secret with `HKDF-SHA256`.
- Optional shared-point output: enable `Show shared point X||Y (MCU verification)` to display the full shared point for MCU/firmware comparison.
- Desktop GUI: built with Python's standard `tkinter` library; no browser or web server is required.

## 运行环境 / Requirements

- Python 3.8+（建议使用较新的 Python 3 版本）
- `cryptography`
- `tkinter`

说明：`tkinter` 通常随 Windows/macOS 的 Python 一起安装。部分 Linux 发行版需要单独安装，例如 Ubuntu/Debian 可使用 `sudo apt install python3-tk`。

---

- Python 3.8+ is recommended.
- `cryptography`
- `tkinter`

Note: `tkinter` is usually bundled with Python on Windows and macOS. Some Linux distributions package it separately, for example `sudo apt install python3-tk` on Ubuntu/Debian.

## 安装与启动 / Installation & Run

```bash
git clone git@github.com:zoujinlin/ecdh_simulator_gui_Repo.git
cd ecdh_simulator_gui_Repo
python -m pip install cryptography
python ecdh_simulator_gui.py
```

如果系统中 `python` 指向 Python 2 或不存在，请改用：

If `python` points to Python 2 or is unavailable, use:

```bash
python3 -m pip install cryptography
python3 ecdh_simulator_gui.py
```

## 使用说明 / Usage

1. 选择曲线<br>
   在 `Select Curve` 下拉框中选择椭圆曲线。当前默认曲线为 `SECP256K1`。切换曲线后，请重新生成或重新输入该曲线对应长度的密钥。

2. 生成或输入 Host 密钥<br>
   点击 `Generate Host Key Pair` 可一次性生成 Host 私钥和公钥。也可以只生成私钥，再点击 `Generate Public Key` 从私钥派生公钥。

3. 生成或输入 Device 密钥<br>
   点击 `Generate Device Key Pair` 可一次性生成 Device 私钥和公钥。也可以手动粘贴已有密钥，用于和外部设备、固件或测试向量对比。

4. 执行密钥交换<br>
   点击 `Perform Key Exchange & Verify` 后，程序会分别计算：
   - Host private key + Device public key
   - Device private key + Host public key

   如果两端共享密钥一致，输出区会显示 `X coordinate matches (shared secret equal)`。

5. 查看派生结果<br>
   输出区会显示 ECDH shared secret X 坐标、C 数组格式、HKDF-SHA256 派生出的 32 字节 session key，以及可选的共享点 `X || Y`。

6. 清空界面<br>
   点击 `Clear All Inputs & Outputs` 可清除输入、输出和内存中的密钥对象。

---

1. Select a curve<br>
   Use the `Select Curve` dropdown to choose an elliptic curve. The default curve is `SECP256K1`. After changing the curve, regenerate or re-enter keys with the correct length for that curve.

2. Generate or enter Host keys<br>
   Click `Generate Host Key Pair` to generate both Host private and public keys. You can also generate only the private key and then click `Generate Public Key` to derive the public key.

3. Generate or enter Device keys<br>
   Click `Generate Device Key Pair` to generate both Device private and public keys. Existing keys can also be pasted manually for comparison with external devices, firmware, or test vectors.

4. Run key exchange<br>
   Click `Perform Key Exchange & Verify`. The application calculates:
   - Host private key + Device public key
   - Device private key + Host public key

   If both sides match, the output area displays `X coordinate matches (shared secret equal)`.

5. Inspect derived values<br>
   The output area shows the ECDH shared-secret X coordinate, C-array output, the 32-byte HKDF-SHA256 session key, and optionally the full shared point `X || Y`.

6. Clear the UI<br>
   Click `Clear All Inputs & Outputs` to clear all inputs, outputs, and cached key objects.

## 密钥格式 / Key Formats

### 私钥 / Private Key

私钥是大端序整数的固定长度字节表示，长度由曲线决定：

Private keys are fixed-length big-endian byte representations of scalar values. The length depends on the selected curve:

| Curve | Private Key Length | Public Key `X || Y` Length |
| --- | ---: | ---: |
| SECP224R1 | 28 bytes | 56 bytes |
| SECP256R1 | 32 bytes | 64 bytes |
| SECP256K1 | 32 bytes | 64 bytes |
| SECP384R1 | 48 bytes | 96 bytes |
| SECP521R1 | 66 bytes | 132 bytes |

### 公钥 / Public Key

界面中的公钥格式为未压缩椭圆曲线点的 `X || Y` 部分，不包含 ANSI X9.62 未压缩点前缀 `0x04`。程序内部加载公钥时会自动补上该前缀。

The displayed public key is the `X || Y` part of an uncompressed elliptic-curve point and does not include the ANSI X9.62 uncompressed-point prefix `0x04`. The application adds this prefix internally when loading the key.

### 十六进制格式 / Hex Formats

标准十六进制：

Standard hex:

```text
0x112233445566
```

C 数组字节格式：

C-array byte format:

```text
0x11 0x22 0x33 0x44 0x55 0x66
```

## 密钥派生参数 / Key Derivation Parameters

ECDH 共享密钥由 `cryptography` 的 `private_key.exchange(ec.ECDH(), peer_public_key)` 计算，输出为共享点的 X 坐标。

The ECDH shared secret is calculated by `private_key.exchange(ec.ECDH(), peer_public_key)` from the `cryptography` package. The result is the shared point's X coordinate.

HKDF 参数如下：

HKDF parameters:

| Parameter | Value |
| --- | --- |
| Algorithm | SHA-256 |
| Output length | 32 bytes |
| Salt | `None` |
| Info | `b"ECDH Key Exchange Session"` |

## 项目结构 / Project Structure

```text
.
├── ecdh_simulator_gui.py   # Tkinter GUI and ECDH/HKDF logic
├── README.md               # Bilingual project documentation
├── LICENSE                 # MIT License
└── .gitignore
```

## 适用场景 / Use Cases

- 学习和演示 ECDH 密钥交换流程。
- 生成 Host/Device 双端测试数据。
- 将 Python 侧结果与 MCU、固件、嵌入式安全芯片或其他语言实现进行对比。
- 验证私钥、公钥、shared secret、HKDF session key 的格式和长度。

---

- Learning and demonstrating the ECDH key-exchange workflow.
- Generating Host/Device test data.
- Comparing Python-side results with MCU, firmware, secure-element, or other language implementations.
- Verifying private key, public key, shared secret, and HKDF session-key formats and lengths.

## 安全说明 / Security Notes

此项目主要用于教学、仿真和调试。不要在生产环境中直接使用界面中生成或粘贴的真实私钥，也不要把真实密钥提交到仓库、日志、截图或 issue 中。

This project is intended for learning, simulation, and debugging. Do not use real production private keys in the GUI, and do not commit real keys to repositories, logs, screenshots, or issues.

## 贡献 / Contributing

欢迎提交 issue 或 pull request 来改进界面、曲线支持、测试向量、文档和嵌入式验证流程。

Issues and pull requests are welcome for UI improvements, additional curve support, test vectors, documentation, and embedded-verification workflows.

## 许可证 / License

本项目基于 MIT License 开源，详见 [LICENSE](LICENSE)。

This project is released under the MIT License. See [LICENSE](LICENSE) for details.
