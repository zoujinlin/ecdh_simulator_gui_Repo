import tkinter as tk
from tkinter import scrolledtext, messagebox
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os
import binascii

class ECDHSimulatorGUI:
    def __init__(self, master):
        self.master = master
        master.title("ECDH Key Exchange Simulator (Multi-Curve Support)")
        # Larger default window; set minimum size; maximize on Windows
        master.geometry("1600x1000")
        master.minsize(1200, 800)
        try:
            master.state('zoomed')
        except Exception:
            pass

        # Supported Curves
        self.supported_curves = {
            "SECP256R1 (NIST P-256)": ec.SECP256R1(),
            "SECP384R1 (NIST P-384)": ec.SECP384R1(),
            "SECP521R1 (NIST P-521)": ec.SECP521R1(),
            "SECP224R1 (NIST P-224)": ec.SECP224R1(),
            "SECP256K1": ec.SECP256K1(),
        }
        self.selected_curve_name = tk.StringVar(master)
        self.selected_curve_name.set("SECP256K1")  # Default curve changed to SECP256K1

        # Stored key objects
        self.host_private_key_obj = None
        self.host_public_key_obj = None
        self.device_private_key_obj = None
        self.device_public_key_obj = None

        self._create_widgets()
        # Pre-cache curve parameters for X||Y computation
        self._init_curve_params()

    def _create_widgets(self):
        # Curve Selection Frame
        curve_selection_frame = tk.LabelFrame(self.master, text="Elliptic Curve Selection", padx=10, pady=10)
        curve_selection_frame.pack(padx=10, pady=5, fill="x")

        tk.Label(curve_selection_frame, text="Select Curve:").pack(side=tk.LEFT, padx=5)
        curve_options = list(self.supported_curves.keys())
        self.curve_menu = tk.OptionMenu(curve_selection_frame, self.selected_curve_name, *curve_options, command=self._on_curve_selection_change)
        self.curve_menu.pack(side=tk.LEFT, padx=5)
        tk.Label(curve_selection_frame, text="Note: After changing curve, regenerate key pairs.").pack(side=tk.LEFT, padx=15)

        # Key Management Frame
        key_management_frame = tk.LabelFrame(self.master, text="Key Management", padx=10, pady=10)
        key_management_frame.pack(padx=10, pady=5, fill="x")

        # Host Section
        host_key_frame = tk.LabelFrame(key_management_frame, text="Host", padx=10, pady=10)
        host_key_frame.pack(side=tk.LEFT, padx=5, pady=5, fill="both", expand=True)

        # Host Private Key
        host_private_key_subframe = tk.LabelFrame(host_key_frame, text="Private Key", padx=5, pady=5)
        host_private_key_subframe.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 5))

        tk.Label(host_private_key_subframe, text="Private Key (Standard Hex):").grid(row=0, column=0, sticky="w")
        self.host_private_key_entry_std = scrolledtext.ScrolledText(host_private_key_subframe, width=60, height=3, wrap=tk.WORD)
        self.host_private_key_entry_std.grid(row=0, column=1, rowspan=2, padx=5, pady=2, sticky="ew")
        
        tk.Label(host_private_key_subframe, text="Private Key (C Array Format):").grid(row=2, column=0, sticky="w")
        self.host_private_key_entry_c = scrolledtext.ScrolledText(host_private_key_subframe, width=60, height=3, wrap=tk.WORD)
        self.host_private_key_entry_c.grid(row=2, column=1, rowspan=2, padx=5, pady=2, sticky="ew")
        tk.Button(host_private_key_subframe, text="Generate Private Key", height=3, command=lambda: self._generate_and_set_private_key("host")).grid(row=0, column=2, rowspan=4, padx=5, pady=5)

        # Host Public Key
        host_public_key_subframe = tk.LabelFrame(host_key_frame, text="Public Key", padx=5, pady=5)
        host_public_key_subframe.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(5, 0))

        tk.Label(host_public_key_subframe, text="Public Key (Standard Hex):").grid(row=0, column=0, sticky="w")
        self.host_public_key_entry_std = scrolledtext.ScrolledText(host_public_key_subframe, width=60, height=3, wrap=tk.WORD)
        self.host_public_key_entry_std.grid(row=0, column=1, rowspan=2, padx=5, pady=2, sticky="ew")
        
        tk.Label(host_public_key_subframe, text="Public Key (C Array Format):").grid(row=2, column=0, sticky="w")
        self.host_public_key_entry_c = scrolledtext.ScrolledText(host_public_key_subframe, width=60, height=3, wrap=tk.WORD)
        self.host_public_key_entry_c.grid(row=2, column=1, rowspan=2, padx=5, pady=2, sticky="ew")
        tk.Button(host_public_key_subframe, text="Generate Public Key", height=3, command=lambda: self._generate_and_set_public_key("host")).grid(row=0, column=2, rowspan=4, padx=5, pady=5)
        
        tk.Button(host_key_frame, text="Generate Host Key Pair", height=2, command=self._generate_full_host_key_pair).grid(row=2, column=0, columnspan=3, pady=5)

        # Device Section
        device_key_frame = tk.LabelFrame(key_management_frame, text="Device", padx=10, pady=10)
        device_key_frame.pack(side=tk.RIGHT, padx=5, pady=5, fill="both", expand=True)

        # Device Private Key
        device_private_key_subframe = tk.LabelFrame(device_key_frame, text="Private Key", padx=5, pady=5)
        device_private_key_subframe.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 5))

        tk.Label(device_private_key_subframe, text="Private Key (Standard Hex):").grid(row=0, column=0, sticky="w")
        self.device_private_key_entry_std = scrolledtext.ScrolledText(device_private_key_subframe, width=60, height=3, wrap=tk.WORD)
        self.device_private_key_entry_std.grid(row=0, column=1, rowspan=2, padx=5, pady=2, sticky="ew")
        
        tk.Label(device_private_key_subframe, text="Private Key (C Array Format):").grid(row=2, column=0, sticky="w")
        self.device_private_key_entry_c = scrolledtext.ScrolledText(device_private_key_subframe, width=60, height=3, wrap=tk.WORD)
        self.device_private_key_entry_c.grid(row=2, column=1, rowspan=2, padx=5, pady=2, sticky="ew")
        tk.Button(device_private_key_subframe, text="Generate Private Key", height=3, command=lambda: self._generate_and_set_private_key("device")).grid(row=0, column=2, rowspan=4, padx=5, pady=5)

        # Device Public Key
        device_public_key_subframe = tk.LabelFrame(device_key_frame, text="Public Key", padx=5, pady=5)
        device_public_key_subframe.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(5, 0))

        tk.Label(device_public_key_subframe, text="Public Key (Standard Hex):").grid(row=0, column=0, sticky="w")
        self.device_public_key_entry_std = scrolledtext.ScrolledText(device_public_key_subframe, width=60, height=3, wrap=tk.WORD)
        self.device_public_key_entry_std.grid(row=0, column=1, rowspan=2, padx=5, pady=2, sticky="ew")
        
        tk.Label(device_public_key_subframe, text="Public Key (C Array Format):").grid(row=2, column=0, sticky="w")
        self.device_public_key_entry_c = scrolledtext.ScrolledText(device_public_key_subframe, width=60, height=3, wrap=tk.WORD)
        self.device_public_key_entry_c.grid(row=2, column=1, rowspan=2, padx=5, pady=2, sticky="ew")
        tk.Button(device_public_key_subframe, text="Generate Public Key", height=3, command=lambda: self._generate_and_set_public_key("device")).grid(row=0, column=2, rowspan=4, padx=5, pady=5)

        tk.Button(device_key_frame, text="Generate Device Key Pair", height=2, command=self._generate_full_device_key_pair).grid(row=2, column=0, columnspan=3, pady=5)

        # Exchange Frame
        exchange_frame = tk.LabelFrame(self.master, text="ECDH Shared Secret & Derived Session Key", padx=10, pady=10)
        exchange_frame.pack(padx=10, pady=5, fill="x")

        tk.Button(exchange_frame, text="Perform Key Exchange & Verify", height=2, command=self._perform_ecdh_exchange).pack(pady=5)

        # Option: show X||Y
        options_frame = tk.Frame(exchange_frame)
        options_frame.pack(fill="x", pady=3)
        self.show_point_xy_var = tk.BooleanVar(value=False)
        tk.Checkbutton(options_frame, text="Show shared point X||Y (MCU verification)", variable=self.show_point_xy_var).pack(anchor="w", padx=4)

        # Output areas
        shared_secret_output_frame = tk.Frame(exchange_frame)
        shared_secret_output_frame.pack(fill="x", pady=5)

        host_shared_secret_subframe = tk.LabelFrame(shared_secret_output_frame, text="Host Shared Secret & Derived Key", padx=5, pady=5)
        host_shared_secret_subframe.pack(side=tk.LEFT, padx=5, fill="both", expand=True)
        self.host_exchange_output = scrolledtext.ScrolledText(host_shared_secret_subframe, width=60, height=18, wrap=tk.WORD)
        self.host_exchange_output.pack(padx=5, pady=5, fill="both", expand=True)

        device_shared_secret_subframe = tk.LabelFrame(shared_secret_output_frame, text="Device Shared Secret & Derived Key", padx=5, pady=5)
        device_shared_secret_subframe.pack(side=tk.RIGHT, padx=5, fill="both", expand=True)
        self.device_exchange_output = scrolledtext.ScrolledText(device_shared_secret_subframe, width=60, height=18, wrap=tk.WORD)
        self.device_exchange_output.pack(padx=5, pady=5, fill="both", expand=True)

        tk.Button(self.master, text="Clear All Inputs & Outputs", height=2, command=self._clear_all).pack(pady=10)

    # Unified text helpers
    def _get_widget_text(self, widget):
        try:
            return widget.get("1.0", tk.END).strip()
        except Exception:
            return widget.get().strip()

    def _set_widget_text(self, widget, text):
        try:
            widget.delete("1.0", tk.END)
            widget.insert("1.0", text)
        except Exception:
            widget.delete(0, tk.END)
            widget.insert(0, text)

    def _clear_widget_text(self, widget):
        try:
            widget.delete("1.0", tk.END)
        except Exception:
            widget.delete(0, tk.END)

    # Check if either Standard or C-array field has content
    def _widget_has_text(self, widget):
        try:
            return bool(widget.get("1.0", tk.END).strip())
        except Exception:
            return bool(widget.get().strip())
    def _either_has_text(self, widget_std, widget_c):
        return self._widget_has_text(widget_std) or self._widget_has_text(widget_c)

    def _on_curve_selection_change(self, *args):
        print(f"Selected curve: {self.selected_curve_name.get()}")
        self._clear_all_key_objects()
        messagebox.showinfo("Curve Changed", "Curve switched. Regenerate all key pairs for the new curve.")

    def _format_bytes_to_std_hex(self, byte_data):
        return "0x" + byte_data.hex()

    def _format_bytes_to_c_array_hex(self, byte_data):
        return " ".join([f"0x{b:02x}" for b in byte_data])

    def _parse_std_hex_input(self, hex_str, expected_bytes_len=None):
        if hex_str.startswith(("0x", "0X")):
            hex_str = hex_str[2:]
        if not hex_str:
            raise ValueError("Hex string cannot be empty.")
        if len(hex_str) % 2 != 0:
            raise ValueError("Hex string length must be even.")
        try:
            byte_data = binascii.unhexlify(hex_str)
        except binascii.Error:
            raise ValueError("Invalid hex string.")
        if expected_bytes_len is not None and len(byte_data) != expected_bytes_len:
            raise ValueError(f"Expected {expected_bytes_len} bytes, got {len(byte_data)}.")
        return byte_data

    def _parse_c_array_hex_input(self, hex_str, expected_bytes_len=None):
        hex_parts = hex_str.split()
        byte_list = []
        for part in hex_parts:
            if part.startswith(("0x", "0X")):
                part = part[2:]
            if not part:
                raise ValueError("Empty hex byte.")
            if len(part) != 2:
                raise ValueError(f"Hex byte '{part}' length must be 2.")
            try:
                byte_list.append(int(part, 16))
            except ValueError:
                raise ValueError(f"Invalid hex byte: '{part}'.")
        byte_data = bytes(byte_list)
        if expected_bytes_len is not None and len(byte_data) != expected_bytes_len:
            raise ValueError(f"Expected {expected_bytes_len} bytes, got {len(byte_data)}.")
        return byte_data

    def _get_key_entries(self, party_name, key_type):
        if party_name == "host":
            if key_type == "private":
                return self.host_private_key_entry_std, self.host_private_key_entry_c
            elif key_type == "public":
                return self.host_public_key_entry_std, self.host_public_key_entry_c
        elif party_name == "device":
            if key_type == "private":
                return self.device_private_key_entry_std, self.device_private_key_entry_c
            elif key_type == "public":
                return self.device_public_key_entry_std, self.device_public_key_entry_c
        return None, None

    def _update_key_entries(self, party_name, key_type, byte_data):
        entry_std, entry_c = self._get_key_entries(party_name, key_type)
        if entry_std and entry_c:
            std_text = self._format_bytes_to_std_hex(byte_data)
            c_text = self._format_bytes_to_c_array_hex(byte_data)
            self._set_widget_text(entry_std, std_text)
            self._set_widget_text(entry_c, c_text)

    def _get_current_curve(self):
        return self.supported_curves[self.selected_curve_name.get()]

    def _get_key_length(self):
        curve = self._get_current_curve()
        if isinstance(curve, ec.SECP256R1):
            private_key_bits = 256
        elif isinstance(curve, ec.SECP384R1):
            private_key_bits = 384
        elif isinstance(curve, ec.SECP521R1):
            private_key_bits = 521
        elif isinstance(curve, ec.SECP224R1):
            private_key_bits = 224
        elif isinstance(curve, ec.SECP256K1):
            private_key_bits = 256
        else:
            raise ValueError(f"Unsupported curve '{self.selected_curve_name.get()}'.")
        private_key_bytes_len = (private_key_bits + 7) // 8
        public_key_bytes_xy_len = private_key_bytes_len * 2
        return private_key_bytes_len, public_key_bytes_xy_len

    def _generate_key_pair_object(self):
        curve = self._get_current_curve()
        private_key = ec.generate_private_key(curve, default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    def _generate_and_set_private_key(self, party_name):
        try:
            private_key_len, _ = self._get_key_length()
            private_key_obj, _ = self._generate_key_pair_object()
            private_key_int = private_key_obj.private_numbers().private_value
            private_key_bytes = private_key_int.to_bytes(private_key_len, byteorder='big')
            self._update_key_entries(party_name, "private", private_key_bytes)
            if party_name == "host":
                self.host_private_key_obj = private_key_obj
            elif party_name == "device":
                self.device_private_key_obj = private_key_obj
            messagebox.showinfo("Success", f"{party_name.capitalize()} private key generated.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate {party_name} private key: {e}")

    def _generate_and_set_public_key(self, party_name):
        try:
            private_key_len, public_key_xy_len = self._get_key_length()
            current_curve_obj = self._get_current_curve()
            entry_std_priv, entry_c_priv = self._get_key_entries(party_name, "private")
            private_key_bytes = None
            private_key_obj_to_use = None
            std_text = self._get_widget_text(entry_std_priv)
            c_text = self._get_widget_text(entry_c_priv)
            if std_text:
                try:
                    private_key_bytes = self._parse_std_hex_input(std_text, private_key_len)
                except ValueError:
                    pass
            if private_key_bytes is None and c_text:
                try:
                    private_key_bytes = self._parse_c_array_hex_input(c_text, private_key_len)
                except ValueError:
                    pass
            if private_key_bytes:
                try:
                    private_value_int = int.from_bytes(private_key_bytes, byteorder='big')
                    private_key_obj_to_use = ec.derive_private_key(private_value_int, current_curve_obj, default_backend())
                    if not isinstance(private_key_obj_to_use.curve, type(current_curve_obj)):
                        messagebox.showwarning("Warning", f"Private key curve mismatch ({self.selected_curve_name.get()}); generating new key pair.")
                        raise ValueError("Curve mismatch.")
                except Exception as e:
                    messagebox.showwarning("Warning", f"Cannot load provided private key: {e}. Generating new key pair.")
                    private_key_obj_to_use, _ = self._generate_key_pair_object()
                    private_key_int = private_key_obj_to_use.private_numbers().private_value
                    private_key_bytes = private_key_int.to_bytes(private_key_len, byteorder='big')
                    self._update_key_entries(party_name, "private", private_key_bytes)
            else:
                private_key_obj_to_use, _ = self._generate_key_pair_object()
                private_key_int = private_key_obj_to_use.private_numbers().private_value
                private_key_bytes = private_key_int.to_bytes(private_key_len, byteorder='big')
                self._update_key_entries(party_name, "private", private_key_bytes)

            public_key_obj = private_key_obj_to_use.public_key()
            public_key_bytes_raw = public_key_obj.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            public_key_xy_bytes = public_key_bytes_raw[1:]
            self._update_key_entries(party_name, "public", public_key_xy_bytes)

            if party_name == "host":
                self.host_private_key_obj = private_key_obj_to_use
                self.host_public_key_obj = public_key_obj
            elif party_name == "device":
                self.device_private_key_obj = private_key_obj_to_use
                self.device_public_key_obj = public_key_obj
            messagebox.showinfo("Success", f"{party_name.capitalize()} public key generated.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate {party_name} public key: {e}")

    def _generate_full_host_key_pair(self):
        try:
            private_key_len, public_key_xy_len = self._get_key_length()
            self.host_private_key_obj, self.host_public_key_obj = self._generate_key_pair_object()
            private_key_int = self.host_private_key_obj.private_numbers().private_value
            private_key_bytes = private_key_int.to_bytes(private_key_len, byteorder='big')
            self._update_key_entries("host", "private", private_key_bytes)
            public_key_bytes_raw = self.host_public_key_obj.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            public_key_xy_bytes = public_key_bytes_raw[1:]
            self._update_key_entries("host", "public", public_key_xy_bytes)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate Host key pair: {e}")

    def _generate_full_device_key_pair(self):
        try:
            private_key_len, public_key_xy_len = self._get_key_length()
            self.device_private_key_obj, self.device_public_key_obj = self._generate_key_pair_object()
            private_key_int = self.device_private_key_obj.private_numbers().private_value
            private_key_bytes = private_key_int.to_bytes(private_key_len, byteorder='big')
            self._update_key_entries("device", "private", private_key_bytes)
            public_key_bytes_raw = self.device_public_key_obj.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            public_key_xy_bytes = public_key_bytes_raw[1:]
            self._update_key_entries("device", "public", public_key_xy_bytes)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate Device key pair: {e}")

    # Curve parameters for computing X||Y shared point
    def _init_curve_params(self):
        self._curve_params = {
            "SECP256R1 (NIST P-256)": {
                "p": 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
                "a": -3,
                "b": 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
                "length": 32
            },
            "SECP384R1 (NIST P-384)": {
                "p": 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
                "a": -3,
                "b": 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
                "length": 48
            },
            "SECP521R1 (NIST P-521)": {
                "p": 0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
                "a": -3,
                "b": 0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00,
                "length": 66
            },
            "SECP224R1 (NIST P-224)": {
                "p": 0xffffffffffffffffffffffffffffffff000000000000000000000001,
                "a": -3,
                "b": 0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4,
                "length": 28
            },
            "SECP256K1": {
                "p": 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
                "a": 0,
                "b": 7,
                "length": 32
            }
        }

    def _mod_inv(self, x, p):
        return pow(x, -1, p)

    def _point_double(self, x1, y1, a, p):
        s = ((3 * x1 * x1 + a) * self._mod_inv(2 * y1 % p, p)) % p
        x3 = (s * s - 2 * x1) % p
        y3 = (s * (x1 - x3) - y1) % p
        return x3, y3

    def _point_add(self, x1, y1, x2, y2, a, p):
        if x1 == x2 and y1 == y2:
            return self._point_double(x1, y1, a, p)
        if x1 == x2:
            return None
        s = ((y2 - y1) * self._mod_inv((x2 - x1) % p, p)) % p
        x3 = (s * s - x1 - x2) % p
        y3 = (s * (x1 - x3) - y1) % p
        return x3, y3

    def _scalar_mult(self, k, x, y, a, p):
        result = None
        addend = (x, y)
        while k > 0:
            if k & 1:
                if result is None:
                    result = addend
                else:
                    r = self._point_add(result[0], result[1], addend[0], addend[1], a, p)
                    if r is None:
                        return None
                    result = r
            addend = self._point_double(addend[0], addend[1], a, p)
            k >>= 1
        return result

    def _compute_shared_point_xy(self, private_key_obj, peer_public_key_obj):
        curve_name = self.selected_curve_name.get()
        if curve_name not in self._curve_params:
            raise ValueError("Curve params not available.")
        params = self._curve_params[curve_name]
        p = params["p"]; a = params["a"]; length = params["length"]
        peer_nums = peer_public_key_obj.public_numbers()
        Qx = peer_nums.x
        Qy = peer_nums.y
        d = private_key_obj.private_numbers().private_value
        R = self._scalar_mult(d, Qx, Qy, a, p)
        if R is None:
            raise ValueError("Point at infinity.")
        Rx, Ry = R
        x_bytes = Rx.to_bytes(length, 'big')
        y_bytes = Ry.to_bytes(length, 'big')
        return x_bytes, y_bytes

    def _perform_ecdh_exchange(self):
        self.host_exchange_output.delete("1.0", tk.END)
        self.device_exchange_output.delete("1.0", tk.END)

        host_private_key_for_exchange = None
        device_private_key_for_exchange = None
        loaded_host_public_key = None
        loaded_device_public_key = None
        
        private_key_len, public_key_xy_len = self._get_key_length()
        current_curve_obj = self._get_current_curve()

        try:
            # Host keys
            if self.host_private_key_obj and self.host_public_key_obj and isinstance(self.host_private_key_obj.curve, type(current_curve_obj)):
                host_private_key_for_exchange = self.host_private_key_obj
                loaded_host_public_key = self.host_public_key_obj
            else:
                host_private_key_bytes = None
                std_text = self._get_widget_text(self.host_private_key_entry_std)
                c_text = self._get_widget_text(self.host_private_key_entry_c)
                if std_text:
                    try:
                        host_private_key_bytes = self._parse_std_hex_input(std_text, private_key_len)
                    except ValueError:
                        pass
                if host_private_key_bytes is None and c_text:
                    try:
                        host_private_key_bytes = self._parse_c_array_hex_input(c_text, private_key_len)
                    except ValueError:
                        pass
                if host_private_key_bytes is None:
                    if not self._either_has_text(self.host_private_key_entry_std, self.host_private_key_entry_c):
                        messagebox.showwarning("Warning", "Enter or generate Host private key.")
                    else:
                        messagebox.showerror("Error", "Host private key invalid.")
                    return
                host_private_value_int = int.from_bytes(host_private_key_bytes, byteorder='big')
                try:
                    host_private_key_for_exchange = ec.derive_private_key(host_private_value_int, current_curve_obj, default_backend())
                except Exception as e:
                    messagebox.showerror("Error", f"Host private key invalid: {e}")
                    return

                host_public_key_bytes_xy = None
                std_pub = self._get_widget_text(self.host_public_key_entry_std)
                c_pub = self._get_widget_text(self.host_public_key_entry_c)
                if std_pub:
                    try:
                        host_public_key_bytes_xy = self._parse_std_hex_input(std_pub, public_key_xy_len)
                    except ValueError:
                        pass
                if host_public_key_bytes_xy is None and c_pub:
                    try:
                        host_public_key_bytes_xy = self._parse_c_array_hex_input(c_pub, public_key_xy_len)
                    except ValueError:
                        pass
                if host_public_key_bytes_xy is None:
                    if not self._either_has_text(self.host_public_key_entry_std, self.host_public_key_entry_c):
                        messagebox.showwarning("Warning", "Enter or generate Host public key.")
                    else:
                        messagebox.showerror("Error", "Host public key invalid.")
                    return
                full_host_public_key_bytes = b'\x04' + host_public_key_bytes_xy
                try:
                    loaded_host_public_key = ec.EllipticCurvePublicKey.from_encoded_point(current_curve_obj, full_host_public_key_bytes)
                except Exception as e:
                    messagebox.showerror("Error", f"Host public key invalid: {e}")
                    return
                if host_private_key_for_exchange.public_key().public_bytes(
                    encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint
                )[1:] != loaded_host_public_key.public_bytes(
                    encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint
                )[1:]:
                    messagebox.showwarning("Warning", "Host key mismatch. Using derived public key.")
                    loaded_host_public_key = host_private_key_for_exchange.public_key()

            # Device keys
            if self.device_private_key_obj and self.device_public_key_obj and isinstance(self.device_private_key_obj.curve, type(current_curve_obj)):
                device_private_key_for_exchange = self.device_private_key_obj
                loaded_device_public_key = self.device_public_key_obj
            else:
                device_private_key_bytes = None
                std_text = self._get_widget_text(self.device_private_key_entry_std)
                c_text = self._get_widget_text(self.device_private_key_entry_c)
                if std_text:
                    try:
                        device_private_key_bytes = self._parse_std_hex_input(std_text, private_key_len)
                    except ValueError:
                        pass
                if device_private_key_bytes is None and c_text:
                    try:
                        device_private_key_bytes = self._parse_c_array_hex_input(c_text, private_key_len)
                    except ValueError:
                        pass
                if device_private_key_bytes is None:
                    if not self._either_has_text(self.device_private_key_entry_std, self.device_private_key_entry_c):
                        messagebox.showwarning("Warning", "Enter or generate Device private key.")
                    else:
                        messagebox.showerror("Error", "Device private key invalid.")
                    return
                device_private_value_int = int.from_bytes(device_private_key_bytes, byteorder='big')
                try:
                    device_private_key_for_exchange = ec.derive_private_key(device_private_value_int, current_curve_obj, default_backend())
                except Exception as e:
                    messagebox.showerror("Error", f"Device private key invalid: {e}")
                    return

                device_public_key_bytes_xy = None
                std_pub = self._get_widget_text(self.device_public_key_entry_std)
                c_pub = self._get_widget_text(self.device_public_key_entry_c)
                if std_pub:
                    try:
                        device_public_key_bytes_xy = self._parse_std_hex_input(std_pub, public_key_xy_len)
                    except ValueError:
                        pass
                if device_public_key_bytes_xy is None and c_pub:
                    try:
                        device_public_key_bytes_xy = self._parse_c_array_hex_input(c_pub, public_key_xy_len)
                    except ValueError:
                        pass
                if device_public_key_bytes_xy is None:
                    if not self._either_has_text(self.device_public_key_entry_std, self.device_public_key_entry_c):
                        messagebox.showwarning("Warning", "Enter or generate Device public key.")
                    else:
                        messagebox.showerror("Error", "Device public key invalid.")
                    return
                full_device_public_key_bytes = b'\x04' + device_public_key_bytes_xy
                try:
                    loaded_device_public_key = ec.EllipticCurvePublicKey.from_encoded_point(current_curve_obj, full_device_public_key_bytes)
                except Exception as e:
                    messagebox.showerror("Error", f"Device public key invalid: {e}")
                    return
                if device_private_key_for_exchange.public_key().public_bytes(
                    encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint
                )[1:] != loaded_device_public_key.public_bytes(
                    encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint
                )[1:]:
                    messagebox.showwarning("Warning", "Device key mismatch. Using derived public key.")
                    loaded_device_public_key = device_private_key_for_exchange.public_key()

        except ValueError as ve:
            messagebox.showerror("Input Error", f"Key parse error: {ve}")
            return
        except Exception as e:
            messagebox.showerror("Error", f"Key load error: {e}")
            return

        # Host shared secret
        host_shared_secret = None
        try:
            if not host_private_key_for_exchange or not loaded_device_public_key:
                messagebox.showerror("Error", "Missing Host or Device key.")
                return
            host_shared_secret = host_private_key_for_exchange.exchange(ec.ECDH(), loaded_device_public_key)
            self.host_exchange_output.insert(tk.END, f"[Host] Standard shared secret (X only) length: {len(host_shared_secret)} bytes\n")
            self.host_exchange_output.insert(tk.END, f"[Host] Shared Secret X (Hex):\n{self._format_bytes_to_std_hex(host_shared_secret)}\n")
            self.host_exchange_output.insert(tk.END, f"[Host] Shared Secret X (C Array):\n{self._format_bytes_to_c_array_hex(host_shared_secret)}\n\n")
            if self.show_point_xy_var.get():
                try:
                    x_bytes, y_bytes = self._compute_shared_point_xy(host_private_key_for_exchange, loaded_device_public_key)
                    self.host_exchange_output.insert(tk.END, f"[Host] Shared Point X||Y (Hex):\n{self._format_bytes_to_std_hex(x_bytes + y_bytes)}\n")
                    self.host_exchange_output.insert(tk.END, f"[Host] X matches exchange() output: {'YES' if x_bytes == host_shared_secret else 'NO'}\n")
                    self.host_exchange_output.insert(tk.END, f"[Host] Y (Hex):\n{self._format_bytes_to_std_hex(y_bytes)}\n\n")
                except Exception as e:
                    self.host_exchange_output.insert(tk.END, f"[Host] Failed to compute X||Y: {e}\n\n")
            info = b"ECDH Key Exchange Session"
            hkdf_key_len = hashes.SHA256.digest_size
            host_derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=hkdf_key_len,
                salt=None,
                info=info,
                backend=default_backend()
            ).derive(host_shared_secret)
            self.host_exchange_output.insert(tk.END, f"[Host] Derived session key (HKDF SHA256, len={hkdf_key_len}) Hex:\n{self._format_bytes_to_std_hex(host_derived_key)}\n")
            self.host_exchange_output.insert(tk.END, f"[Host] Derived session key (C Array):\n{self._format_bytes_to_c_array_hex(host_derived_key)}\n")
            self.host_exchange_output.insert(tk.END, f"[Host] Derived key length: {len(host_derived_key)} bytes\n\n")
        except Exception as e:
            self.host_exchange_output.insert(tk.END, f"Host shared secret error: {e}\n")
            messagebox.showerror("Error", f"Host shared secret error: {e}")

        # Device shared secret
        device_shared_secret = None
        try:
            if not device_private_key_for_exchange or not loaded_host_public_key:
                messagebox.showerror("Error", "Missing Host or Device key.")
                return
            device_shared_secret = device_private_key_for_exchange.exchange(ec.ECDH(), loaded_host_public_key)
            self.device_exchange_output.insert(tk.END, f"[Device] Standard shared secret (X only) length: {len(device_shared_secret)} bytes\n")
            self.device_exchange_output.insert(tk.END, f"[Device] Shared Secret X (Hex):\n{self._format_bytes_to_std_hex(device_shared_secret)}\n")
            self.device_exchange_output.insert(tk.END, f"[Device] Shared Secret X (C Array):\n{self._format_bytes_to_c_array_hex(device_shared_secret)}\n\n")
            if self.show_point_xy_var.get():
                try:
                    x_bytes2, y_bytes2 = self._compute_shared_point_xy(device_private_key_for_exchange, loaded_host_public_key)
                    self.device_exchange_output.insert(tk.END, f"[Device] Shared Point X||Y (Hex):\n{self._format_bytes_to_std_hex(x_bytes2 + y_bytes2)}\n")
                    self.device_exchange_output.insert(tk.END, f"[Device] X matches exchange() output: {'YES' if x_bytes2 == device_shared_secret else 'NO'}\n")
                    self.device_exchange_output.insert(tk.END, f"[Device] Y (Hex):\n{self._format_bytes_to_std_hex(y_bytes2)}\n\n")
                except Exception as e:
                    self.device_exchange_output.insert(tk.END, f"[Device] Failed to compute X||Y: {e}\n\n")
            info = b"ECDH Key Exchange Session"
            hkdf_key_len = hashes.SHA256.digest_size
            device_derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=hkdf_key_len,
                salt=None,
                info=info,
                backend=default_backend()
            ).derive(device_shared_secret)
            self.device_exchange_output.insert(tk.END, f"[Device] Derived session key (HKDF SHA256, len={hkdf_key_len}) Hex:\n{self._format_bytes_to_std_hex(device_derived_key)}\n")
            self.device_exchange_output.insert(tk.END, f"[Device] Derived session key (C Array):\n{self._format_bytes_to_c_array_hex(device_derived_key)}\n")
            self.device_exchange_output.insert(tk.END, f"[Device] Derived key length: {len(device_derived_key)} bytes\n\n")
        except Exception as e:
            self.device_exchange_output.insert(tk.END, f"Device shared secret error: {e}\n")
            messagebox.showerror("Error", f"Device shared secret error: {e}")

        # Verify X
        if host_shared_secret is not None and device_shared_secret is not None:
            if host_shared_secret == device_shared_secret:
                self.host_exchange_output.insert(tk.END, "\n✅ X coordinate matches (shared secret equal)")
                self.device_exchange_output.insert(tk.END, "\n✅ X coordinate matches (shared secret equal)")
            else:
                self.host_exchange_output.insert(tk.END, "\n❌ X coordinate mismatch")
                self.device_exchange_output.insert(tk.END, "\n❌ X coordinate mismatch")
                messagebox.showerror("Error", "Shared secrets (X) mismatch.")

    def _clear_all_key_objects(self):
        self.host_private_key_obj = None
        self.host_public_key_obj = None
        self.device_private_key_obj = None
        self.device_public_key_obj = None

    def _clear_all(self):
        self._clear_widget_text(self.host_private_key_entry_std)
        self._clear_widget_text(self.host_private_key_entry_c)
        self._clear_widget_text(self.host_public_key_entry_std)
        self._clear_widget_text(self.host_public_key_entry_c)
        self._clear_widget_text(self.device_private_key_entry_std)
        self._clear_widget_text(self.device_private_key_entry_c)
        self._clear_widget_text(self.device_public_key_entry_std)
        self._clear_widget_text(self.device_public_key_entry_c)
        self.host_exchange_output.delete("1.0", tk.END)
        self.device_exchange_output.delete("1.0", tk.END)
        self._clear_all_key_objects()

if __name__ == "__main__":
    root = tk.Tk()
    gui = ECDHSimulatorGUI(root)
    root.mainloop()

