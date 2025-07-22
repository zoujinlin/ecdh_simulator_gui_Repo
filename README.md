# ecdh_simulator_gui_Repo
ECDH Key Exchange Simulator (Multi-Curve Support)

Overview
This Python-based GUI application simulates the Elliptic Curve Diffie-Hellman (ECDH) key exchange protocol. It allows users to generate and manage ECDH private and public key pairs for two parties (Host and Device), perform the key exchange, and derive shared secrets and session keys. The simulator supports multiple standard elliptic curves, providing a visual and interactive way to understand the ECDH process.

Features
Multi-Curve Support: Select from various standard elliptic curves (e.g., SECP256R1, SECP384R1, SECP521R1, SECP224R1, SECP256K1).

Key Pair Generation: Easily generate new private and public key pairs for both Host and Device.

Flexible Key Input: Input private and public keys in both standard hexadecimal and C-array hexadecimal formats.

Shared Secret Calculation: Automatically computes the shared secret between the Host and Device.

Session Key Derivation: Uses HKDF (HMAC-based Key Derivation Function) with SHA256 to derive a robust session key from the shared secret.

Verification: Instantly verifies if the derived shared secrets match between the Host and Device.

Clear Interface: A clean and intuitive graphical user interface built with tkinter.

Requirements
Before running the application, ensure you have Python 3 installed. You'll also need the cryptography library.

You can install the necessary library using pip:

Bash

pip install cryptography
How to Run
Save the code: Save the provided Python code into a file named ecdh_simulator_gui.py.

Open a terminal/command prompt: Navigate to the directory where you saved the file.

Run the application: Execute the following command:

Bash

python ecdh_simulator_gui.py
Usage
Select an Elliptic Curve: Choose your desired curve from the "Elliptic Curve Algorithm Selection" dropdown menu. Remember to regenerate keys if you change the curve.

Generate Keys:

Click "Generate Host Key Pair" and "Generate Device Key Pair" to automatically create new private and public keys for both parties.

Alternatively, you can manually enter private and public keys in either "Standard Hex" or "C Array Format" fields, then click "Generate Private Key" or "Generate Public Key" to update the associated fields or derive missing keys.

Perform Key Exchange: Once both Host and Device have valid key pairs, click the "Perform Key Exchange & Verify" button.

View Results: The "Host Shared Secret & Derived Key" and "Device Shared Secret & Derived Key" sections will display the calculated shared secrets and derived session keys, along with a verification status.

Clear All: Use the "Clear All Inputs & Outputs" button to reset the application.

Project Structure
.
└── ecdh_simulator_gui.py  # Main application script
Contributing
Feel free to fork this repository, open issues, or submit pull requests. Any contributions to improve the simulator are welcome!

License
This project is open-source and available under the MIT License.
