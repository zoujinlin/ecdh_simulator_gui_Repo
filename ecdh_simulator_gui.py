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
        master.geometry("1400x950") # Increased window width
        # master.geometry("1250x950") # Original window size

        # Supported Curves and their corresponding cryptography objects
        self.supported_curves = {
            "SECP256R1 (NIST P-256)": ec.SECP256R1(),
            "SECP384R1 (NIST P-384)": ec.SECP384R1(),
            "SECP521R1 (NIST P-521)": ec.SECP521R1(),
            "SECP224R1 (NIST P-224)": ec.SECP224R1(),
            "SECP256K1": ec.SECP256K1(),
            # Brainpool, FRP256V1, SM2, SM2TEST are NOT directly supported by 'cryptography' ec.Curve objects.
            # Adding them would require a significantly more complex implementation or additional libraries.
        }
        self.selected_curve_name = tk.StringVar(master)
        self.selected_curve_name.set("SECP256R1 (NIST P-256)") # Default curve

        # Store key objects
        self.host_private_key_obj = None
        self.host_public_key_obj = None
        self.device_private_key_obj = None
        self.device_public_key_obj = None

        self._create_widgets()

    def _create_widgets(self):
        # Curve Selection Frame
        curve_selection_frame = tk.LabelFrame(self.master, text="Elliptic Curve Algorithm Selection", padx=10, pady=10)
        curve_selection_frame.pack(padx=10, pady=5, fill="x")

        tk.Label(curve_selection_frame, text="Select Curve:").pack(side=tk.LEFT, padx=5)
        curve_options = list(self.supported_curves.keys())
        self.curve_menu = tk.OptionMenu(curve_selection_frame, self.selected_curve_name, *curve_options, command=self._on_curve_selection_change)
        self.curve_menu.pack(side=tk.LEFT, padx=5)
        tk.Label(curve_selection_frame, text="Note: After changing the curve, please regenerate key pairs.").pack(side=tk.LEFT, padx=15)


        # Key Management Frame - contains left and right sections
        key_management_frame = tk.LabelFrame(self.master, text="Key Management", padx=10, pady=10)
        key_management_frame.pack(padx=10, pady=5, fill="x")

        # Host Key Section (Left)
        host_key_frame = tk.LabelFrame(key_management_frame, text="Host", padx=10, pady=10)
        host_key_frame.pack(side=tk.LEFT, padx=5, pady=5, fill="both", expand=True)

        # Host Private Key Frame
        host_private_key_subframe = tk.LabelFrame(host_key_frame, text="Private Key", padx=5, pady=5)
        host_private_key_subframe.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 5))

        tk.Label(host_private_key_subframe, text="Private Key (Standard Hex):").grid(row=0, column=0, sticky="w")
        self.host_private_key_entry_std = tk.Entry(host_private_key_subframe, width=35)
        self.host_private_key_entry_std.grid(row=0, column=1, rowspan=2, padx=5, pady=2, sticky="ew")
        
        tk.Label(host_private_key_subframe, text="Private Key (C Array Format):").grid(row=2, column=0, sticky="w")
        self.host_private_key_entry_c = tk.Entry(host_private_key_subframe, width=35)
        self.host_private_key_entry_c.grid(row=2, column=1, rowspan=2, padx=5, pady=2, sticky="ew")
        tk.Button(host_private_key_subframe, text="Generate Private Key", height=3, command=lambda: self._generate_and_set_private_key("host")).grid(row=0, column=2, rowspan=4, padx=5, pady=5)


        # Host Public Key Frame
        host_public_key_subframe = tk.LabelFrame(host_key_frame, text="Public Key", padx=5, pady=5)
        host_public_key_subframe.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(5, 0)) # Position below private key frame

        tk.Label(host_public_key_subframe, text="Public Key (Standard Hex):").grid(row=0, column=0, sticky="w")
        self.host_public_key_entry_std = tk.Entry(host_public_key_subframe, width=35)
        self.host_public_key_entry_std.grid(row=0, column=1, rowspan=2, padx=5, pady=2, sticky="ew")
        
        tk.Label(host_public_key_subframe, text="Public Key (C Array Format):").grid(row=2, column=0, sticky="w")
        self.host_public_key_entry_c = tk.Entry(host_public_key_subframe, width=35)
        self.host_public_key_entry_c.grid(row=2, column=1, rowspan=2, padx=5, pady=2, sticky="ew")
        tk.Button(host_public_key_subframe, text="Generate Public Key", height=3, command=lambda: self._generate_and_set_public_key("host")).grid(row=0, column=2, rowspan=4, padx=5, pady=5)
        
        tk.Button(host_key_frame, text="Generate Host Key Pair", height=2, command=self._generate_full_host_key_pair).grid(row=2, column=0, columnspan=3, pady=5) # Below public key frame


        # Device Key Section (Right)
        device_key_frame = tk.LabelFrame(key_management_frame, text="Device", padx=10, pady=10)
        device_key_frame.pack(side=tk.RIGHT, padx=5, pady=5, fill="both", expand=True)

        # Device Private Key Frame
        device_private_key_subframe = tk.LabelFrame(device_key_frame, text="Private Key", padx=5, pady=5)
        device_private_key_subframe.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 5))

        tk.Label(device_private_key_subframe, text="Private Key (Standard Hex):").grid(row=0, column=0, sticky="w")
        self.device_private_key_entry_std = tk.Entry(device_private_key_subframe, width=35)
        self.device_private_key_entry_std.grid(row=0, column=1, rowspan=2, padx=5, pady=2, sticky="ew")
        
        tk.Label(device_private_key_subframe, text="Private Key (C Array Format):").grid(row=2, column=0, sticky="w")
        self.device_private_key_entry_c = tk.Entry(device_private_key_subframe, width=35)
        self.device_private_key_entry_c.grid(row=2, column=1, rowspan=2, padx=5, pady=2, sticky="ew")
        tk.Button(device_private_key_subframe, text="Generate Private Key", height=3, command=lambda: self._generate_and_set_private_key("device")).grid(row=0, column=2, rowspan=4, padx=5, pady=5)

        # Device Public Key Frame
        device_public_key_subframe = tk.LabelFrame(device_key_frame, text="Public Key", padx=5, pady=5)
        device_public_key_subframe.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(5, 0))

        tk.Label(device_public_key_subframe, text="Public Key (Standard Hex):").grid(row=0, column=0, sticky="w")
        self.device_public_key_entry_std = tk.Entry(device_public_key_subframe, width=35)
        self.device_public_key_entry_std.grid(row=0, column=1, rowspan=2, padx=5, pady=2, sticky="ew")
        
        tk.Label(device_public_key_subframe, text="Public Key (C Array Format):").grid(row=2, column=0, sticky="w")
        self.device_public_key_entry_c = tk.Entry(device_public_key_subframe, width=35)
        self.device_public_key_entry_c.grid(row=2, column=1, rowspan=2, padx=5, pady=2, sticky="ew")
        tk.Button(device_public_key_subframe, text="Generate Public Key", height=3, command=lambda: self._generate_and_set_public_key("device")).grid(row=0, column=2, rowspan=4, padx=5, pady=5)

        tk.Button(device_key_frame, text="Generate Device Key Pair", height=2, command=self._generate_full_device_key_pair).grid(row=2, column=0, columnspan=3, pady=5)


        # Key Exchange and Shared Secret Display Frame
        exchange_frame = tk.LabelFrame(self.master, text="ECDH Shared Secret & Derived Session Key", padx=10, pady=10)
        exchange_frame.pack(padx=10, pady=5, fill="x")

        tk.Button(exchange_frame, text="Perform Key Exchange & Verify", height=2, command=self._perform_ecdh_exchange).pack(pady=5)

        # Shared Secret Output Frame - left and right sections
        shared_secret_output_frame = tk.Frame(exchange_frame)
        shared_secret_output_frame.pack(fill="x", pady=5)

        # Host Shared Secret Output (Left)
        host_shared_secret_subframe = tk.LabelFrame(shared_secret_output_frame, text="Host Shared Secret & Derived Key", padx=5, pady=5)
        host_shared_secret_subframe.pack(side=tk.LEFT, padx=5, fill="both", expand=True)
        self.host_exchange_output = scrolledtext.ScrolledText(host_shared_secret_subframe, width=60, height=18, wrap=tk.WORD) # Increased height
        self.host_exchange_output.pack(padx=5, pady=5, fill="both", expand=True)

        # Device Shared Secret Output (Right)
        device_shared_secret_subframe = tk.LabelFrame(shared_secret_output_frame, text="Device Shared Secret & Derived Key", padx=5, pady=5)
        device_shared_secret_subframe.pack(side=tk.RIGHT, padx=5, fill="both", expand=True)
        self.device_exchange_output = scrolledtext.ScrolledText(device_shared_secret_subframe, width=60, height=18, wrap=tk.WORD) # Increased height
        self.device_exchange_output.pack(padx=5, pady=5, fill="both", expand=True)

        # Clear Button
        tk.Button(self.master, text="Clear All Inputs & Outputs", height=2, command=self._clear_all).pack(pady=10)

    def _on_curve_selection_change(self, *args):
        """Called when a new curve is selected from the dropdown."""
        print(f"Selected curve: {self.selected_curve_name.get()}")
        self._clear_all_key_objects() # Clear existing key objects when curve changes
        messagebox.showinfo("Curve Changed", "Elliptic curve has been switched. Please regenerate all key pairs to ensure the new curve is used.")


    def _format_bytes_to_std_hex(self, byte_data):
        """Formats bytes to a standard concatenated hex string with 0x prefix."""
        return "0x" + byte_data.hex()

    def _format_bytes_to_c_array_hex(self, byte_data):
        """Formats bytes to a space-separated hex string with 0x prefix for each byte."""
        return " ".join([f"0x{b:02x}" for b in byte_data])

    def _parse_std_hex_input(self, hex_str, expected_bytes_len=None):
        """Parses a standard concatenated hex string (e.g., '0xaabbcc') to bytes and verifies length."""
        if hex_str.startswith("0x") or hex_str.startswith("0X"):
            hex_str = hex_str[2:]
        
        if not hex_str:
            raise ValueError("Hex string cannot be empty.")
        
        if len(hex_str) % 2 != 0:
            raise ValueError("Hex string length must be even.")

        try:
            byte_data = binascii.unhexlify(hex_str)
        except binascii.Error:
            raise ValueError("Invalid hex string.")

        # Only check length if expected_bytes_len is provided
        if expected_bytes_len is not None and len(byte_data) != expected_bytes_len:
            raise ValueError(f"Expected length {expected_bytes_len} bytes, but got {len(byte_data)} bytes.")
        
        return byte_data

    def _parse_c_array_hex_input(self, hex_str, expected_bytes_len=None):
        """Parses a space-separated hex string (e.g., '0xAA 0xBB') to bytes and verifies length."""
        hex_parts = hex_str.split()
        byte_list = []
        for part in hex_parts:
            if part.startswith("0x") or part.startswith("0X"):
                part = part[2:]
            
            if not part:
                raise ValueError("Hex byte string cannot be empty.")
            if len(part) != 2:
                raise ValueError(f"Hex byte '{part}' length must be 2.")
            try:
                byte_list.append(int(part, 16))
            except ValueError:
                raise ValueError(f"Invalid hex byte: '{part}'.")
        
        byte_data = bytes(byte_list)

        # Only check length if expected_bytes_len is provided
        if expected_bytes_len is not None and len(byte_data) != expected_bytes_len:
            raise ValueError(f"Expected length {expected_bytes_len} bytes, but got {len(byte_data)} bytes.")
        
        return byte_data

    def _get_key_entries(self, party_name, key_type):
        """Helper to get the correct entry widgets based on party and key type."""
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
        """Updates both standard and C-array hex entry fields."""
        entry_std, entry_c = self._get_key_entries(party_name, key_type)
        if entry_std and entry_c:
            entry_std.delete(0, tk.END)
            entry_std.insert(0, self._format_bytes_to_std_hex(byte_data))
            entry_c.delete(0, tk.END)
            entry_c.insert(0, self._format_bytes_to_c_array_hex(byte_data))

    def _get_current_curve(self):
        """Returns the currently selected elliptic curve object."""
        return self.supported_curves[self.selected_curve_name.get()]

    def _get_key_length(self):
        """Returns the expected byte length for private and public keys based on the selected curve."""
        curve = self._get_current_curve()
        
        private_key_bits = 0
        if isinstance(curve, ec.SECP256R1):
            private_key_bits = 256
        elif isinstance(curve, ec.SECP384R1):
            private_key_bits = 384
        elif isinstance(curve, ec.SECP521R1):
            private_key_bits = 521 # Note: 521 bits requires 66 bytes
        elif isinstance(curve, ec.SECP224R1):
            private_key_bits = 224
        elif isinstance(curve, ec.SECP256K1):
            private_key_bits = 256
        else:
            # Fallback for unknown curves or if a specific curve isn't handled here
            # For simplicity, we'll assume a common 256-bit default or raise an error.
            # In a real-world scenario, you'd want a more robust way to get curve params.
            raise ValueError(f"Unsupported curve '{self.selected_curve_name.get()}' for length determination.")
        
        private_key_bytes_len = (private_key_bits + 7) // 8 # Convert bits to bytes, rounding up
        public_key_bytes_xy_len = private_key_bytes_len * 2 # Public key (X || Y) length is twice the private key length
        
        return private_key_bytes_len, public_key_bytes_xy_len


    def _generate_key_pair_object(self):
        """Internal helper function to generate a single key pair object using the selected curve."""
        curve = self._get_current_curve()
        private_key = ec.generate_private_key(curve, default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    def _generate_and_set_private_key(self, party_name):
        """Generates and sets the private key hex string for the specified party into both input boxes."""
        try:
            private_key_len, _ = self._get_key_length()
            private_key_obj, _ = self._generate_key_pair_object() 
            private_key_int = private_key_obj.private_numbers().private_value
            private_key_bytes = private_key_int.to_bytes(private_key_len, byteorder='big')

            self._update_key_entries(party_name, "private", private_key_bytes)

            # Update internally stored key objects for subsequent operations
            if party_name == "host":
                self.host_private_key_obj = private_key_obj
            elif party_name == "device":
                self.device_private_key_obj = private_key_obj
            
            messagebox.showinfo("Success", f"{party_name.capitalize()} private key generated and set.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate {party_name} private key: {e}")

    def _generate_and_set_public_key(self, party_name):
        """Generates and sets the public key based on private key input, or generates a new key pair if no private key."""
        try:
            private_key_len, public_key_xy_len = self._get_key_length()
            current_curve_obj = self._get_current_curve()

            entry_std_priv, entry_c_priv = self._get_key_entries(party_name, "private")
            
            private_key_bytes = None
            private_key_obj_to_use = None

            # Try parsing from standard hex first, then C-array hex
            if entry_std_priv.get():
                try:
                    private_key_bytes = self._parse_std_hex_input(entry_std_priv.get(), private_key_len)
                except ValueError:
                    pass # Try C-array next
            
            if private_key_bytes is None and entry_c_priv.get():
                try:
                    private_key_bytes = self._parse_c_array_hex_input(entry_c_priv.get(), private_key_len)
                except ValueError:
                    pass # Will generate new if both fail

            if private_key_bytes:
                try:
                    private_value_int = int.from_bytes(private_key_bytes, byteorder='big')
                    private_numbers = ec.EllipticCurvePrivateNumbers(
                        private_value=private_value_int,
                        public_numbers=None, # Public numbers can be None here, it will be derived
                    )
                    private_key_obj_to_use = ec.EllipticCurvePrivateKey.from_private_numbers(private_numbers, default_backend()) 
                    # Verify curve matches
                    if not isinstance(private_key_obj_to_use.curve, type(current_curve_obj)):
                         messagebox.showwarning("Warning", f"The entered private key does not match the currently selected elliptic curve ({self.selected_curve_name.get()}). A new key pair will be generated.")
                         raise ValueError("Curve mismatch for loaded private key.")

                except Exception as e:
                    messagebox.showwarning("Warning", f"Could not create key object from existing private key input (or curve mismatch): {e}\nGenerating a new key pair.")
                    private_key_obj_to_use, _ = self._generate_key_pair_object()
                    private_key_int = private_key_obj_to_use.private_numbers().private_value
                    private_key_bytes = private_key_int.to_bytes(private_key_len, byteorder='big')
                    self._update_key_entries(party_name, "private", private_key_bytes) # Update private key fields
            else:
                messagebox.showwarning("Warning", "No valid private key input, generating a new key pair.")
                private_key_obj_to_use, _ = self._generate_key_pair_object() 
                private_key_int = private_key_obj_to_use.private_numbers().private_value
                private_key_bytes = private_key_int.to_bytes(private_key_len, byteorder='big')
                self._update_key_entries(party_name, "private", private_key_bytes) # Update private key fields

            public_key_obj = private_key_obj_to_use.public_key()
            public_key_bytes_raw = public_key_obj.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            # Remove leading 0x04 byte for (X || Y) format
            public_key_xy_bytes = public_key_bytes_raw[1:] 

            self._update_key_entries(party_name, "public", public_key_xy_bytes)

            # Update internally stored key objects
            if party_name == "host":
                self.host_private_key_obj = private_key_obj_to_use
                self.host_public_key_obj = public_key_obj
            elif party_name == "device":
                self.device_private_key_obj = private_key_obj_to_use
                self.device_public_key_obj = public_key_obj
            
            messagebox.showinfo("Success", f"{party_name.capitalize()} public key generated and set.")

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
            # No messagebox here as per previous request
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
            # No messagebox here as per previous request
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate Device key pair: {e}")


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
            # --- Load Host Keys ---
            if self.host_private_key_obj and self.host_public_key_obj and \
               isinstance(self.host_private_key_obj.curve, type(current_curve_obj)):
                # Use internally stored keys if they match the selected curve
                host_private_key_for_exchange = self.host_private_key_obj
                loaded_host_public_key = self.host_public_key_obj
            else:
                # Try to load from standard hex first, then C-array hex for private key
                host_private_key_bytes = None
                if self.host_private_key_entry_std.get():
                    try:
                        host_private_key_bytes = self._parse_std_hex_input(self.host_private_key_entry_std.get(), private_key_len)
                    except ValueError:
                        pass
                if host_private_key_bytes is None and self.host_private_key_entry_c.get():
                    try:
                        host_private_key_bytes = self._parse_c_array_hex_input(self.host_private_key_entry_c.get(), private_key_len)
                    except ValueError:
                        pass
                
                if not host_private_key_bytes:
                    messagebox.showwarning("Warning", "Please enter or generate a private key for the Host.")
                    return

                host_private_value_int = int.from_bytes(host_private_key_bytes, byteorder='big')
                host_private_numbers = ec.EllipticCurvePrivateNumbers(
                    private_value=host_private_value_int, public_numbers=None
                )
                # Ensure the private key is loaded for the currently selected curve
                try:
                    host_private_key_for_exchange = ec.EllipticCurvePrivateKey.from_private_numbers(host_private_numbers, default_backend())
                    if not isinstance(host_private_key_for_exchange.curve, type(current_curve_obj)):
                        raise ValueError("Private key does not match the selected curve.")
                except Exception as e:
                    messagebox.showerror("Error", f"Host private key incompatible with current curve: {e}")
                    return

                # Try to load from standard hex, then C-array hex for public key
                host_public_key_bytes_xy = None
                if self.host_public_key_entry_std.get():
                    try:
                        host_public_key_bytes_xy = self._parse_std_hex_input(self.host_public_key_entry_std.get(), public_key_xy_len)
                    except ValueError:
                        pass
                if host_public_key_bytes_xy is None and self.host_public_key_entry_c.get():
                    try:
                        host_public_key_bytes_xy = self._parse_c_array_hex_input(self.host_public_key_entry_c.get(), public_key_xy_len)
                    except ValueError:
                        pass
                
                if not host_public_key_bytes_xy:
                    messagebox.showwarning("Warning", "Please enter or generate a public key for the Host.")
                    return
                
                full_host_public_key_bytes = b'\x04' + host_public_key_bytes_xy
                try:
                    loaded_host_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                        current_curve_obj, full_host_public_key_bytes
                    )
                except Exception as e:
                    messagebox.showerror("Error", f"Host public key format is incorrect or does not match the curve: {e}")
                    return
                
                # Validate loaded public key against derived public key
                if host_private_key_for_exchange.public_key().public_bytes(
                    encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint
                )[1:] != loaded_host_public_key.public_bytes(
                    encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint
                )[1:]:
                    messagebox.showwarning("Warning", "Host's entered private key and public key do not match. The public key derived from the private key will be used for calculation.")
                    loaded_host_public_key = host_private_key_for_exchange.public_key()


            # --- Load Device Keys ---
            if self.device_private_key_obj and self.device_public_key_obj and \
               isinstance(self.device_private_key_obj.curve, type(current_curve_obj)):
                # Use internally stored keys if they match the selected curve
                device_private_key_for_exchange = self.device_private_key_obj
                loaded_device_public_key = self.device_public_key_obj
            else:
                # Try to load from standard hex, then C-array hex for private key
                device_private_key_bytes = None
                if self.device_private_key_entry_std.get():
                    try:
                        device_private_key_bytes = self._parse_std_hex_input(self.device_private_key_entry_std.get(), private_key_len)
                    except ValueError:
                        pass
                if device_private_key_bytes is None and self.device_private_key_entry_c.get():
                    try:
                        device_private_key_bytes = self._parse_c_array_hex_input(self.device_private_key_entry_c.get(), private_key_len)
                    except ValueError:
                        pass
                
                if not device_private_key_bytes:
                    messagebox.showwarning("Warning", "Please enter or generate a private key for the Device.")
                    return

                device_private_value_int = int.from_bytes(device_private_key_bytes, byteorder='big')
                device_private_numbers = ec.EllipticCurvePrivateNumbers(
                    private_value=device_private_value_int, public_numbers=None,
                )
                try:
                    device_private_key_for_exchange = ec.EllipticCurvePrivateKey.from_private_numbers(device_private_numbers, default_backend())
                    if not isinstance(device_private_key_for_exchange.curve, type(current_curve_obj)):
                        raise ValueError("Private key does not match the selected curve.")
                except Exception as e:
                    messagebox.showerror("Error", f"Device private key incompatible with current curve: {e}")
                    return

                # Try to load from standard hex, then C-array hex for public key
                device_public_key_bytes_xy = None
                if self.device_public_key_entry_std.get():
                    try:
                        device_public_key_bytes_xy = self._parse_std_hex_input(self.device_public_key_entry_std.get(), public_key_xy_len)
                    except ValueError:
                        pass
                if device_public_key_bytes_xy is None and self.device_public_key_entry_c.get():
                    try:
                        device_public_key_bytes_xy = self._parse_c_array_hex_input(self.device_public_key_entry_c.get(), public_key_xy_len)
                    except ValueError:
                        pass
                
                if not device_public_key_bytes_xy:
                    messagebox.showwarning("Warning", "Please enter or generate a public key for the Device.")
                    return

                full_device_public_key_bytes = b'\x04' + device_public_key_bytes_xy
                try:
                    loaded_device_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                        current_curve_obj, full_device_public_key_bytes
                    )
                except Exception as e:
                    messagebox.showerror("Error", f"Device public key format is incorrect or does not match the curve: {e}")
                    return
                
                # Validate loaded public key against derived public key
                if device_private_key_for_exchange.public_key().public_bytes(
                    encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint
                )[1:] != loaded_device_public_key.public_bytes(
                    encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint
                )[1:]:
                    messagebox.showwarning("Warning", "Device's entered private key and public key do not match. The public key derived from the private key will be used for calculation.")
                    loaded_device_public_key = device_private_key_for_exchange.public_key()

        except ValueError as ve:
            messagebox.showerror("Input Error", f"Key parsing failed or length mismatch: {ve}")
            return
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while loading keys: {e}")
            return

        # Host calculates shared secret
        host_shared_secret = None
        try:
            if not host_private_key_for_exchange or not loaded_device_public_key:
                messagebox.showerror("Error", "Host or Device key not loaded correctly, cannot perform key exchange.")
                return

            host_shared_secret = host_private_key_for_exchange.exchange(ec.ECDH(), loaded_device_public_key)
            self.host_exchange_output.insert(tk.END, f"Shared Secret Length: {len(host_shared_secret)} bytes\n")
            self.host_exchange_output.insert(tk.END, f"Shared Secret (Standard Hex):\n{self._format_bytes_to_std_hex(host_shared_secret)}\n")
            self.host_exchange_output.insert(tk.END, f"Shared Secret (C Array Format):\n{self._format_bytes_to_c_array_hex(host_shared_secret)}\n\n")

            info = b"ECDH Key Exchange Session"
            # HKDF key length should be derived based on the hash algorithm, usually 32 for SHA256
            hkdf_key_len = hashes.SHA256.digest_size 
            host_derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=hkdf_key_len,
                salt=None,
                info=info,
                backend=default_backend()
            ).derive(host_shared_secret)
            self.host_exchange_output.insert(tk.END, f"Derived Session Key (Standard Hex):\n{self._format_bytes_to_std_hex(host_derived_key)}\n")
            self.host_exchange_output.insert(tk.END, f"Derived Session Key (C Array Format):\n{self._format_bytes_to_c_array_hex(host_derived_key)}\n")
            self.host_exchange_output.insert(tk.END, f"Derived Session Key Length: {len(host_derived_key)} bytes\n")

        except Exception as e:
            self.host_exchange_output.insert(tk.END, f"Host failed to calculate shared secret: {e}\n")
            messagebox.showerror("Error", f"Host failed to calculate shared secret: {e}")

        # Device calculates shared secret
        device_shared_secret = None
        try:
            if not device_private_key_for_exchange or not loaded_host_public_key:
                messagebox.showerror("Error", "Host or Device key not loaded correctly, cannot perform key exchange.")
                return

            device_shared_secret = device_private_key_for_exchange.exchange(ec.ECDH(), loaded_host_public_key)
            self.device_exchange_output.insert(tk.END, f"Shared Secret Length: {len(device_shared_secret)} bytes\n")
            self.device_exchange_output.insert(tk.END, f"Shared Secret (Standard Hex):\n{self._format_bytes_to_std_hex(device_shared_secret)}\n")
            self.device_exchange_output.insert(tk.END, f"Shared Secret (C Array Format):\n{self._format_bytes_to_c_array_hex(device_shared_secret)}\n\n")

            info = b"ECDH Key Exchange Session"
            hkdf_key_len = hashes.SHA256.digest_size
            device_derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=hkdf_key_len,
                salt=None,
                info=info,
                backend=default_backend()
            ).derive(device_shared_secret)
            self.device_exchange_output.insert(tk.END, f"Derived Session Key (Standard Hex):\n{self._format_bytes_to_std_hex(device_derived_key)}\n")
            self.device_exchange_output.insert(tk.END, f"Derived Session Key (C Array Format):\n{self._format_bytes_to_c_array_hex(device_derived_key)}\n")
            self.device_exchange_output.insert(tk.END, f"Derived Session Key Length: {len(device_derived_key)} bytes\n")

        except Exception as e:
            self.device_exchange_output.insert(tk.END, f"Device failed to calculate shared secret: {e}\n")
            messagebox.showerror("Error", f"Device failed to calculate shared secret: {e}")
        
        # Verify results
        if host_shared_secret is not None and device_shared_secret is not None:
            if host_shared_secret == device_shared_secret:
                self.host_exchange_output.insert(tk.END, "\n✅ Verification Success: Shared secrets match!")
                self.device_exchange_output.insert(tk.END, "\n✅ Verification Success: Shared secrets match!")
            else:
                self.host_exchange_output.insert(tk.END, "\n❌ Verification Failed: Shared secrets do NOT match!")
                self.device_exchange_output.insert(tk.END, "\n❌ Verification Failed: Shared secrets do NOT match!")
                messagebox.showerror("Error", "Shared secrets do NOT match! Please check keys.")

    def _clear_all_key_objects(self):
        """Clears only the internally stored key objects, useful when changing curve."""
        self.host_private_key_obj = None
        self.host_public_key_obj = None
        self.device_private_key_obj = None
        self.device_public_key_obj = None

    def _clear_all(self):
        # Clear input boxes
        self.host_private_key_entry_std.delete(0, tk.END)
        self.host_private_key_entry_c.delete(0, tk.END)
        self.host_public_key_entry_std.delete(0, tk.END)
        self.host_public_key_entry_c.delete(0, tk.END)
        self.device_private_key_entry_std.delete(0, tk.END)
        self.device_private_key_entry_c.delete(0, tk.END)
        self.device_public_key_entry_std.delete(0, tk.END)
        self.device_public_key_entry_c.delete(0, tk.END)

        # Clear output boxes
        self.host_exchange_output.delete("1.0", tk.END)
        self.device_exchange_output.delete("1.0", tk.END)

        # Clear internally stored key objects
        self._clear_all_key_objects()


if __name__ == "__main__":
    root = tk.Tk()
    gui = ECDHSimulatorGUI(root)
    root.mainloop()

    