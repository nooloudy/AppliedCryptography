import os
from datetime import datetime
from tkinter import Tk, Label, Entry, Button, Text, END, messagebox, LabelFrame
from rsa_algorithm import generate_keys, encrypt_message, decrypt_message

class RSAApp:
    def __init__(self, master):
        self.master = master
        master.title("RSA Encryption/Decryption")
        master.geometry("700x1100")  
        master.resizable(False, False)  

        self.ensure_directories()

        key_frame = LabelFrame(master, text="Key Generation", padx=10, pady=10, font=("Arial", 12, "bold"))
        key_frame.pack(padx=10, pady=10, fill="both")

        self.p_label = Label(key_frame, text="Enter prime number p:", font=("Arial", 10))
        self.p_label.grid(row=0, column=0, sticky="w", pady=5)
        self.p_entry = Entry(key_frame, width=30)
        self.p_entry.grid(row=0, column=1, pady=5)

        self.q_label = Label(key_frame, text="Enter prime number q:", font=("Arial", 10))
        self.q_label.grid(row=1, column=0, sticky="w", pady=5)
        self.q_entry = Entry(key_frame, width=30)
        self.q_entry.grid(row=1, column=1, pady=5)

        self.generate_key_button = Button(key_frame, text="Generate Keys", command=self.generate_keys, bg="#4CAF50", fg="white", font=("Arial", 10, "bold"))
        self.generate_key_button.grid(row=2, column=0, columnspan=2, pady=10)

        self.public_key_label = Label(key_frame, text="Public Key:", font=("Arial", 10))
        self.public_key_label.grid(row=3, column=0, sticky="w", pady=5)
        self.public_key_text = Text(key_frame, height=2, width=50)
        self.public_key_text.grid(row=3, column=1, pady=5)

        self.private_key_label = Label(key_frame, text="Private Key:", font=("Arial", 10))
        self.private_key_label.grid(row=4, column=0, sticky="w", pady=5)
        self.private_key_text = Text(key_frame, height=2, width=50)
        self.private_key_text.grid(row=4, column=1, pady=5)

        self.save_keys_button = Button(key_frame, text="Save Keys", command=self.save_keys, bg="#2196F3", fg="white", font=("Arial", 10, "bold"))
        self.save_keys_button.grid(row=5, column=0, columnspan=2, pady=10)

        encrypt_frame = LabelFrame(master, text="Encryption", padx=10, pady=10, font=("Arial", 12, "bold"))
        encrypt_frame.pack(padx=10, pady=10, fill="both")

        self.plaintext_label = Label(encrypt_frame, text="Enter plaintext:", font=("Arial", 10))
        self.plaintext_label.grid(row=0, column=0, sticky="w", pady=5)
        self.plaintext_text = Text(encrypt_frame, height=5, width=50)
        self.plaintext_text.grid(row=0, column=1, pady=5)

        self.encrypt_button = Button(encrypt_frame, text="Encrypt", command=self.encrypt, bg="#4CAF50", fg="white", font=("Arial", 10, "bold"))
        self.encrypt_button.grid(row=1, column=0, columnspan=2, pady=10)

        self.encrypted_label = Label(encrypt_frame, text="Encrypted Text:", font=("Arial", 10))
        self.encrypted_label.grid(row=2, column=0, sticky="w", pady=5)
        self.encrypted_text = Text(encrypt_frame, height=5, width=50)
        self.encrypted_text.grid(row=2, column=1, pady=5)

        self.save_encrypted_button = Button(encrypt_frame, text="Save Encrypted Text", command=self.save_encrypted_text, bg="#2196F3", fg="white", font=("Arial", 10, "bold"))
        self.save_encrypted_button.grid(row=3, column=0, columnspan=2, pady=10)

        decrypt_frame = LabelFrame(master, text="Decryption", padx=10, pady=10, font=("Arial", 12, "bold"))
        decrypt_frame.pack(padx=10, pady=10, fill="both")

        self.ciphertext_label = Label(decrypt_frame, text="Enter encrypted text:", font=("Arial", 10))
        self.ciphertext_label.grid(row=0, column=0, sticky="w", pady=5)
        self.ciphertext_text = Text(decrypt_frame, height=5, width=50)
        self.ciphertext_text.grid(row=0, column=1, pady=5)

        self.decrypt_button = Button(decrypt_frame, text="Decrypt", command=self.decrypt, bg="#FF5722", fg="white", font=("Arial", 10, "bold"))
        self.decrypt_button.grid(row=1, column=0, columnspan=2, pady=10)

        self.decrypted_label = Label(decrypt_frame, text="Decrypted Text:", font=("Arial", 10))
        self.decrypted_label.grid(row=2, column=0, sticky="w", pady=5)
        self.decrypted_text = Text(decrypt_frame, height=5, width=50)
        self.decrypted_text.grid(row=2, column=1, pady=5)

        self.save_decrypted_button = Button(decrypt_frame, text="Save Decrypted Text", command=self.save_decrypted_text, bg="#2196F3", fg="white", font=("Arial", 10, "bold"))
        self.save_decrypted_button.grid(row=3, column=0, columnspan=2, pady=10)

        clear_button = Button(master, text="Clear All", command=self.clear_all, bg="#FF0000", fg="white", font=("Arial", 10, "bold"))
        clear_button.pack(pady=10)


    def ensure_directories(self):
        os.makedirs("keys", exist_ok=True)
        os.makedirs("encrypted", exist_ok=True)
        os.makedirs("decrypted", exist_ok=True)

    def save_keys(self):
        public_key = self.public_key_text.get("1.0", END).strip()
        private_key = self.private_key_text.get("1.0", END).strip()

        if not public_key or not private_key:
            messagebox.showerror("Error", "Keys are empty! Generate keys first.")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        with open(f"keys/public_key_{timestamp}.txt", "w") as pub_file:
            pub_file.write(public_key)
        with open(f"keys/private_key_{timestamp}.txt", "w") as priv_file:
            priv_file.write(private_key)

        messagebox.showinfo("Success", "Keys saved successfully!")

    def save_encrypted_text(self):
        encrypted_text = self.encrypted_text.get("1.0", END).strip()

        if not encrypted_text:
            messagebox.showerror("Error", "Encrypted text is empty!")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        with open(f"encrypted/encrypted_text_{timestamp}.txt", "w") as enc_file:
            enc_file.write(encrypted_text)

        messagebox.showinfo("Success", "Encrypted text saved successfully!")

    def save_decrypted_text(self):
        decrypted_text = self.decrypted_text.get("1.0", END).strip()

        if not decrypted_text:
            messagebox.showerror("Error", "Decrypted text is empty!")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        with open(f"decrypted/decrypted_text_{timestamp}.txt", "w") as dec_file:
            dec_file.write(decrypted_text)

        messagebox.showinfo("Success", "Decrypted text saved successfully!")
    
    def generate_keys(self):
        def is_prime(num):
            if num <= 1:
                return False
            for i in range(2, int(num ** 0.5) + 1):
                if num % i == 0:
                    return False
            return True
        try:
            # Получение значений p и q из текстовых полей
            p = int(self.p_entry.get())
            q = int(self.q_entry.get())

            if not is_prime(p) or not is_prime(q):
                messagebox.showerror("Error", "Both numbers must be prime! Please enter valid prime numbers.")
                return

            public_key, private_key = generate_keys(p, q)

            self.public_key_text.delete("1.0", END)
            self.public_key_text.insert("1.0", str(public_key))

            self.private_key_text.delete("1.0", END)
            self.private_key_text.insert("1.0", str(private_key))
        except ValueError:
            messagebox.showerror("Error", "Invalid input! Please enter valid numbers.")
        except Exception as e:
            messagebox.showerror("Error", f"Key generation failed: {e}")

    def encrypt(self):
        try:
            plaintext = self.plaintext_text.get("1.0", END).strip()
            public_key = eval(self.public_key_text.get("1.0", END).strip())
            encrypted_message = encrypt_message(public_key, plaintext)

            self.encrypted_text.delete("1.0", END)
            self.encrypted_text.insert("1.0", encrypted_message)

            self.ciphertext_text.delete("1.0", END)
            self.ciphertext_text.insert("1.0", encrypted_message)
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def decrypt(self):
        try:
            ciphertext = self.ciphertext_text.get("1.0", END).strip()
            private_key = eval(self.private_key_text.get("1.0", END).strip())
            decrypted_message = decrypt_message(private_key, ciphertext)

            self.decrypted_text.delete("1.0", END)
            self.decrypted_text.insert("1.0", decrypted_message)
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

    def clear_all(self):
        """Clear all text fields in the interface."""
        self.p_entry.delete(0, END)
        self.q_entry.delete(0, END)
        self.public_key_text.delete("1.0", END)
        self.private_key_text.delete("1.0", END)
        self.plaintext_text.delete("1.0", END)
        self.encrypted_text.delete("1.0", END)
        self.ciphertext_text.delete("1.0", END)
        self.decrypted_text.delete("1.0", END)

    