# GUI implementation using Tkinter

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from algorithms.rsa_custom import generate_keys as rsa_generate_keys, sign_message as rsa_sign, verify_signature as rsa_verify
from algorithms.dsa_custom import generate_keys as dsa_generate_keys, sign_message as dsa_sign, verify_signature as dsa_verify
from algorithms.elgamal_custom import generate_keys as elgamal_generate_keys, sign_message as elgamal_sign, verify_signature as elgamal_verify
from algorithms.hashing import hash_message
from file_utils import save_to_file, load_from_file, save_public_key, save_private_key, save_message, save_signature
from logger import setup_logger

# Initialize logger
logger = setup_logger()

def launch_app():
    # Initialize the main window
    root = tk.Tk()
    root.title("Digital Signature Application")

    # Variables
    algorithm_var = tk.StringVar(value="RSA")
    hash_var = tk.StringVar(value="SHA-256")
    message_var = tk.StringVar()
    signature_var = tk.StringVar()
    public_key = None
    private_key = None
    public_params = None

    # Functions
    def generate_keys():
        nonlocal public_key, private_key, public_params
        algo = algorithm_var.get()
        if algo == "RSA":
            public_key, private_key = rsa_generate_keys()
        elif algo == "DSA":
            public_params, public_key, private_key = dsa_generate_keys()  # Updated to unpack (p, q, g), y, x
        elif algo == "ElGamal":
            public_params, private_key = elgamal_generate_keys()
            public_key = public_params[2]  # y
        else:
            messagebox.showerror("Error", "Invalid algorithm selected.")
            return
        # Save keys to files
        save_public_key(algo, public_key)
        save_private_key(algo, private_key)
        messagebox.showinfo("Success", f"{algo} keys generated and saved successfully.")
        logger.info(f"{algo} keys generated and saved.")

    def sign_message():
        nonlocal private_key, public_params
        algo = algorithm_var.get()
        message = message_var.get()
        if not private_key:
            messagebox.showerror("Error", "Generate keys first.")
            logger.error("Signing failed: Private key is not generated.")
            return
        if not message:
            messagebox.showerror("Error", "Enter a message to sign.")
            logger.error("Signing failed: Message is empty.")
            return
        try:
            if algo == "RSA":
                signature = rsa_sign(private_key, message, hash_var.get())
            elif algo == "DSA":
                signature = dsa_sign(private_key, message, public_params, hash_var.get())
            elif algo == "ElGamal":
                signature = elgamal_sign(private_key, message, public_params, hash_var.get())
            else:
                raise ValueError("Invalid algorithm selected.")
            signature_var.set(str(signature))
            # Save message and signature to files
            save_message(algo, message)
            save_signature(algo, signature)
            messagebox.showinfo("Success", "Message signed and saved successfully.")
            logger.info(f"Message signed and saved with {algo} using {hash_var.get()}.")
        except Exception as e:
            messagebox.showerror("Error", f"Signing failed: {e}")
            logger.error(f"Signing failed: {e}")

    def verify_message():
        nonlocal public_key, public_params
        algo = algorithm_var.get()
        message = message_var.get()
        signature = signature_var.get()
        if not public_key:
            messagebox.showerror("Error", "Generate keys first.")
            logger.error("Verification failed: Public key is not generated.")
            return
        if not message or not signature:
            messagebox.showerror("Error", "Enter a message and signature to verify.")
            logger.error("Verification failed: Message or signature is empty.")
            return
        try:
            if algo == "RSA":
                valid = rsa_verify(public_key, message, int(signature), hash_var.get())
            elif algo == "DSA":
                r, s = eval(signature)  # Convert string to tuple
                valid = dsa_verify(public_key, message, (r, s), public_params, hash_var.get())
            elif algo == "ElGamal":
                r, s = eval(signature)  # Convert string to tuple
                valid = elgamal_verify(public_key, message, (r, s), public_params, hash_var.get())
            else:
                raise ValueError("Invalid algorithm selected.")
            if valid:
                messagebox.showinfo("Success", "Signature is valid.")
                logger.info(f"Signature verified successfully with {algo}.")
            else:
                messagebox.showerror("Error", "Signature is invalid.")
                logger.error(f"Verification failed: Signature is invalid.")
        except Exception as e:
            messagebox.showerror("Error", f"Verification failed: {e}")
            logger.error(f"Verification failed: {e}")

    # Layout
    ttk.Label(root, text="Algorithm:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
    ttk.Combobox(root, textvariable=algorithm_var, values=["RSA", "DSA", "ElGamal"]).grid(row=0, column=1, padx=5, pady=5)

    ttk.Label(root, text="Hash Algorithm:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
    ttk.Combobox(root, textvariable=hash_var, values=["SHA-256", "SHA-384", "SHA-512"]).grid(row=1, column=1, padx=5, pady=5)

    ttk.Button(root, text="Generate Keys", command=generate_keys).grid(row=2, column=0, columnspan=2, pady=10)

    ttk.Label(root, text="Message:").grid(row=3, column=0, padx=5, pady=5, sticky="w")
    ttk.Entry(root, textvariable=message_var, width=50).grid(row=3, column=1, padx=5, pady=5)

    ttk.Button(root, text="Sign Message", command=sign_message).grid(row=4, column=0, columnspan=2, pady=10)

    ttk.Label(root, text="Signature:").grid(row=5, column=0, padx=5, pady=5, sticky="w")
    ttk.Entry(root, textvariable=signature_var, width=50).grid(row=5, column=1, padx=5, pady=5)

    ttk.Button(root, text="Verify Signature", command=verify_message).grid(row=6, column=0, columnspan=2, pady=10)

    # Run the application
    root.mainloop()
