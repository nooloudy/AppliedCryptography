from datetime import datetime
import os
from tkinter import Tk, Text, Button, Label, StringVar, OptionMenu, messagebox, END
from tkinter.filedialog import asksaveasfilename
from algorithms.rsa import generate_keys as rsa_generate_keys, sign_message as rsa_sign, verify_signature as rsa_verify
from algorithms.elgamal import generate_keys as elgamal_generate_keys, sign_message as elgamal_sign, verify_signature as elgamal_verify
from algorithms.dsa import generate_keys as dsa_generate_keys, sign_message as dsa_sign, verify_signature as dsa_verify


class MainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Digital Signature Application")

        # Variables
        self.algorithm_var = StringVar(value="RSA")
        self.hashing_var = StringVar(value="SHA-256")
        self.finalized_hashing_algorithm = None
        self.private_key = None
        self.public_key = None

        # Selection of Digital Signature Algorithm
        Label(root, text="Select Digital Signature Algorithm:").grid(row=0, column=0, padx=10, pady=5, columnspan=2)
        OptionMenu(root, self.algorithm_var, "RSA", "ElGamal", "DSA", command=self.reset_keys).grid(row=1, column=0, padx=10, pady=5, columnspan=2)

        # Selection of Hashing Algorithm
        Label(root, text="Select Hashing Algorithm:").grid(row=2, column=0, padx=10, pady=5, columnspan=2)
        OptionMenu(root, self.hashing_var, "SHA-256", "SHA-384", "SHA-512").grid(row=3, column=0, padx=10, pady=5, columnspan=2)
        Button(root, text="Accept", command=self.accept_hashing_algorithm).grid(row=4, column=0, padx=10, pady=5, columnspan=2)

        # Key Generation
        Label(root, text="Key Generation:").grid(row=5, column=0, padx=10, pady=5, columnspan=2)
        Button(root, text="Generate Keys", command=self.generate_keys).grid(row=6, column=0, padx=10, pady=5, columnspan=2)

        Label(root, text="Public Key:").grid(row=7, column=0, padx=10, pady=5)
        self.public_key_output = Text(root, height=5, width=40)
        self.public_key_output.grid(row=7, column=1, padx=10, pady=5)

        Label(root, text="Private Key:").grid(row=8, column=0, padx=10, pady=5)
        self.private_key_output = Text(root, height=5, width=40)
        self.private_key_output.grid(row=8, column=1, padx=10, pady=5)

        Button(root, text="Save Public Key", command=self.save_public_key).grid(row=9, column=0, padx=10, pady=5, columnspan=2)

        # Digital Signature Section
        Label(root, text="Creating a Digital Signature:").grid(row=10, column=0, padx=10, pady=5, columnspan=2)

        Label(root, text="Message:").grid(row=11, column=0, padx=10, pady=5)
        self.message_entry = Text(root, height=5, width=40)
        self.message_entry.grid(row=11, column=1, padx=10, pady=5)

        Button(root, text="Save Message", command=self.save_message).grid(row=12, column=0, padx=10, pady=5, columnspan=2)
        Button(root, text="Sign Message", command=self.sign_message).grid(row=13, column=0, padx=10, pady=5, columnspan=2)

        Label(root, text="Digital Signature:").grid(row=14, column=0, padx=10, pady=5)
        self.signature_output = Text(root, height=5, width=40)
        self.signature_output.grid(row=14, column=1, padx=10, pady=5)

        Button(root, text="Save Signature", command=self.save_signature).grid(row=15, column=0, padx=10, pady=5, columnspan=2)

        # Signature Verification Section
        Label(root, text="Signature Verification:").grid(row=16, column=0, padx=10, pady=5, columnspan=2)

        Label(root, text="Message:").grid(row=17, column=0, padx=10, pady=5)
        self.verification_message_entry = Text(root, height=5, width=40)
        self.verification_message_entry.grid(row=17, column=1, padx=10, pady=5)

        Label(root, text="Signature:").grid(row=18, column=0, padx=10, pady=5)
        self.verification_signature_entry = Text(root, height=5, width=40)
        self.verification_signature_entry.grid(row=18, column=1, padx=10, pady=5)

        Button(root, text="Verify Signature", command=self.verify_signature).grid(row=19, column=0, padx=10, pady=5, columnspan=2)

        Label(root, text="Verification Result:").grid(row=20, column=0, padx=10, pady=5)
        self.verification_result = Label(root, text="", fg="blue")
        self.verification_result.grid(row=20, column=1, padx=10, pady=5)

    def reset_keys(self, *args):
        """Reset the keys when the algorithm is changed."""
        self.private_key = None
        self.public_key = None

        self.public_key_output.delete("1.0", END)
        self.private_key_output.delete("1.0", END)

    def generate_keys(self):
        algorithm = self.algorithm_var.get()
        if algorithm == "RSA":
            keys = rsa_generate_keys()
        elif algorithm == "ElGamal":
            keys = elgamal_generate_keys()
        elif algorithm == "DSA":
            keys = dsa_generate_keys()
        else:
            messagebox.showerror("Error", "Invalid algorithm selected.")
            return

        self.private_key = keys["private_key"]
        self.public_key = keys["public_key"]

        self.public_key_output.delete("1.0", END)
        self.public_key_output.insert(END, self.public_key)

        self.private_key_output.delete("1.0", END)
        self.private_key_output.insert(END, self.private_key)

        messagebox.showinfo("Key Generation", f"{algorithm} keys generated successfully!")

    def save_public_key(self):
        """Save the public key to a file with a timestamp and algorithm name."""
        if not self.public_key:
            messagebox.showerror("Error", "No public key to save.")
            return

        os.makedirs("public_keys", exist_ok=True)
        algorithm = self.algorithm_var.get()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_path = os.path.join("public_keys", f"{algorithm}_public_key_{timestamp}.pem")

        with open(file_path, "w") as file:
            file.write(str(self.public_key))

        messagebox.showinfo("Save Public Key", f"Public key saved successfully as {file_path}!")

    def accept_hashing_algorithm(self):
        """Finalize the selected hashing algorithm."""
        self.finalized_hashing_algorithm = self.hashing_var.get()
        messagebox.showinfo("Hashing Algorithm", f"Hashing algorithm '{self.finalized_hashing_algorithm}' accepted!")

    def save_message(self):
        """Save the message to a file."""
        message = self.message_entry.get("1.0", END).strip()
        if not message:
            messagebox.showerror("Error", "No message to save.")
            return

        os.makedirs("messages", exist_ok=True)
        algorithm = self.algorithm_var.get()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_path = os.path.join("messages", f"{algorithm}_message_{timestamp}.txt")

        with open(file_path, "w") as file:
            file.write(message)
        messagebox.showinfo("Save Message", f"Message saved successfully as {file_path}!")

    def sign_message(self):
        """Sign the message."""
        message = self.message_entry.get("1.0", END).strip()
        if not message:
            messagebox.showerror("Error", "No message to sign.")
            return

        if not self.finalized_hashing_algorithm:
            messagebox.showerror("Error", "Please accept a hashing algorithm before signing.")
            return

        if self.finalized_hashing_algorithm == "SHA-256":
            from hashlib import sha256
            hashed_message = sha256(message.encode()).hexdigest()
        elif self.finalized_hashing_algorithm == "SHA-384":
            from hashlib import sha384
            hashed_message = sha384(message.encode()).hexdigest()
        elif self.finalized_hashing_algorithm == "SHA-512":
            from hashlib import sha512
            hashed_message = sha512(message.encode()).hexdigest()
        else:
            messagebox.showerror("Error", "Invalid hashing algorithm selected.")
            return

        algorithm = self.algorithm_var.get()
        if algorithm == "RSA":
            signature = rsa_sign(self.private_key, hashed_message)
        elif algorithm == "ElGamal":
            signature = elgamal_sign(self.private_key, hashed_message)
        elif algorithm == "DSA":
            signature = dsa_sign(self.private_key, hashed_message)
        else:
            messagebox.showerror("Error", "Invalid algorithm selected.")
            return

        self.signature_output.delete("1.0", END)
        self.signature_output.insert(END, str(signature))

        os.makedirs("signatures", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_path = os.path.join("signatures", f"{algorithm}_signature_{timestamp}.sig")

        with open(file_path, "w") as file:
            file.write(str(signature))
        messagebox.showinfo("Sign Message", f"Message signed and signature saved as {file_path}!")

    def save_signature(self):
        """Save the signature to a file."""
        signature = self.signature_output.get("1.0", END).strip()
        if not signature:
            messagebox.showerror("Error", "No signature to save.")
            return

        os.makedirs("signatures", exist_ok=True)
        algorithm = self.algorithm_var.get()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_path = os.path.join("signatures", f"{algorithm}_signature_{timestamp}.sig")

        with open(file_path, "w") as file:
            file.write(signature)
        messagebox.showinfo("Save Signature", f"Signature saved successfully as {file_path}!")

    def verify_signature(self):
        """Verify the digital signature."""
        message = self.verification_message_entry.get("1.0", END).strip()
        signature = self.verification_signature_entry.get("1.0", END).strip()
        if not message or not signature:
            messagebox.showerror("Error", "Please provide both message and signature for verification.")
            return

        if not self.finalized_hashing_algorithm:
            messagebox.showerror("Error", "Please accept a hashing algorithm before verifying.")
            return

        if self.finalized_hashing_algorithm == "SHA-256":
            from hashlib import sha256
            hashed_message = sha256(message.encode()).hexdigest()
        elif self.finalized_hashing_algorithm == "SHA-384":
            from hashlib import sha384
            hashed_message = sha384(message.encode()).hexdigest()
        elif self.finalized_hashing_algorithm == "SHA-512":
            from hashlib import sha512
            hashed_message = sha512(message.encode()).hexdigest()
        else:
            messagebox.showerror("Error", "Invalid hashing algorithm selected.")
            return

        algorithm = self.algorithm_var.get()
        try:
            if algorithm == "RSA":
                valid = rsa_verify(self.public_key, hashed_message, signature)
            elif algorithm == "ElGamal":
                signature = eval(signature)
                valid = elgamal_verify(self.public_key, hashed_message, signature)
            elif algorithm == "DSA":
                valid = dsa_verify(self.public_key, hashed_message, signature)
            else:
                messagebox.showerror("Error", "Invalid algorithm selected.")
                return
        except Exception as e:
            messagebox.showerror("Error", f"Verification failed: {str(e)}")
            return

        if valid:
            self.verification_result.config(text="Signature is valid", fg="green")
        else:
            self.verification_result.config(text="Invalid signature", fg="red")


if __name__ == "__main__":
    root = Tk()
    app = MainWindow(root)
    root.mainloop()