# ECDH Key Exchange Simulator GUI

[简体中文说明](./README.zh-CN.md)

Desktop GUI simulator for exploring the Elliptic Curve Diffie-Hellman (ECDH) key exchange process with multiple standard curves.

## Overview

This project is a Python + tkinter desktop application that demonstrates how two parties derive the same shared secret through ECDH. The interface lets you generate, import, and compare Host/Device key pairs, inspect the shared secret, and derive a session key with HKDF-SHA256.

It is intended for learning, debugging, and interoperability checks when working with raw ECC key material in hexadecimal form.

## Features

- Multi-curve support:
  - SECP256R1 (NIST P-256)
  - SECP384R1 (NIST P-384)
  - SECP521R1 (NIST P-521)
  - SECP224R1 (NIST P-224)
  - SECP256K1 (default)
- Generate Host and Device private/public key pairs
- Import key material in:
  - standard hex format (for example `0x1234abcd`)
  - C-array style hex format (for example `0x12 0x34 0xab 0xcd`)
- Perform ECDH exchange and verify whether both parties derive the same shared secret
- Derive a session key from the shared secret with HKDF-SHA256
- Optionally display the full shared point `X||Y` for MCU / embedded-side verification
- Clear and compare outputs for both communication parties in one screen

## Requirements

- Python 3.9+ recommended
- [cryptography](https://pypi.org/project/cryptography/)
- `tkinter` runtime support

> `tkinter` is usually bundled with the official Python installer on Windows and many macOS builds.  
> On Linux, you may need to install it separately (for example, `python3-tk` on Debian/Ubuntu).

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/zoujinlin/ecdh_simulator_gui_Repo.git
   cd ecdh_simulator_gui_Repo
   ```

2. Install the Python dependency:

   ```bash
   pip install cryptography
   ```

3. Ensure your Python environment has `tkinter` available.

## Run

Start the GUI application from the repository root:

```bash
python ecdh_simulator_gui.py
```

## Usage Example

1. Launch the application.
2. Select an elliptic curve from the dropdown list.
3. Click **Generate Host Key Pair** and **Generate Device Key Pair**.
4. Optionally replace the generated keys with your own data in standard hex or C-array format.
5. Click **Perform Key Exchange & Verify**.
6. Review:
   - Host shared secret output
   - Device shared secret output
   - HKDF-derived session keys
   - verification result showing whether both shared secrets match
7. If needed, enable **Show shared point X||Y (MCU verification)** to inspect the full point coordinates.

### Accepted Key Formats

Standard hex:

```text
0x11223344aabbccdd
```

C-array style hex:

```text
0x11 0x22 0x33 0x44 0xaa 0xbb 0xcc 0xdd
```

## Project Structure

```text
ecdh_simulator_gui_Repo/
├── ecdh_simulator_gui.py   # Main tkinter GUI application
├── README.md               # English documentation
├── README.zh-CN.md         # Simplified Chinese documentation
└── LICENSE                 # MIT license
```

## Notes / Disclaimer

- This project is primarily for learning, simulation, and interoperability verification.
- The displayed keys and secrets are intended for local testing only. Do not use exposed demo key material in real systems.
- If you change the selected curve, regenerate both parties' key pairs before running the exchange again.
- Running the GUI requires a graphical desktop environment; headless servers may not support direct launch.

## License

This project is licensed under the [MIT License](./LICENSE).
