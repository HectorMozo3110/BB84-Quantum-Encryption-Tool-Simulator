import sys
import os
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import base64
import re
import pyperclip
import threading
import time
import json
from fpdf import FPDF
# ----------------------------------------------------------------------------
# Copyright 2025 Hector Mozo
# Licensed under the Apache License, Version 2.0 (the "License");
# ...
# ----------------------------------------------------------------------------


# Extend Python path to allow module imports from parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from bb84_backend.logic.controller import encrypt_file_local, decrypt_file_local

class BB84App:
    def __init__(self, root):
        # Initialize main GUI window
        self.root = root
        self.root.title("BB84 Quantum Encryption Tool (Simulator)")
        self.root.geometry("750x720")
        self.root.configure(bg="#f4f4f4")

        # Internal state
        self.file_path = None
        self.encrypted_data = None
        self.key_b = None

        # Build GUI components
        self.create_widgets()

    def create_widgets(self):
        # Radio buttons for selecting mode: encryption or decryption
        self.mode_var = tk.StringVar(value="encrypt")

        title = tk.Label(self.root, text="BB84 Quantum Encryption / Decryption", font=("Arial", 16, "bold"), bg="#f4f4f4")
        title.pack(pady=10)

        mode_frame = tk.Frame(self.root, bg="#f4f4f4")
        tk.Radiobutton(mode_frame, text="Encrypt", variable=self.mode_var, value="encrypt", bg="#f4f4f4", command=self.update_mode).pack(side=tk.LEFT, padx=10)
        tk.Radiobutton(mode_frame, text="Decrypt", variable=self.mode_var, value="decrypt", bg="#f4f4f4", command=self.update_mode).pack(side=tk.LEFT, padx=10)
        mode_frame.pack(pady=5)

        # File selection button and label
        tk.Button(self.root, text="Select File", command=self.select_file, bg="#d0eaff").pack(pady=5)
        self.file_label = tk.Label(self.root, text="No file selected", bg="#f4f4f4")
        self.file_label.pack(pady=2)

        # Entry field for Key B (only used in decryption mode)
        self.key_frame = tk.Frame(self.root, bg="#f4f4f4")
        self.key_entry = tk.Entry(self.key_frame, width=80)
        self.key_entry.insert(0, "Key B (only for decryption)")
        self.key_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(self.key_frame, text="Import Key File", command=self.import_key_file, bg="#e0ffe0").pack(side=tk.LEFT)
        self.key_frame.pack(pady=5)

        # Buttons to copy or save Key B (only shown after encryption)
        self.copy_button = tk.Button(self.root, text="Copy Key B", command=self.copy_key_b, bg="#ffd0d0")
        self.copy_button.pack(pady=2)
        self.copy_button.pack_forget()

        self.save_key_button = tk.Button(self.root, text="Save Key B to .txt", command=self.save_key_b_to_file, bg="#ffe4b5")
        self.save_key_button.pack(pady=2)
        self.save_key_button.pack_forget()

        # Main execution button
        tk.Button(self.root, text="Run", command=self.run, bg="#c0ffc0").pack(pady=10)
        tk.Button(self.root, text="Download Metrics Report (PDF)", command=self.download_metrics_pdf, bg="#dcdcdc").pack(pady=5)

        # Output log area
        self.output_box = ScrolledText(self.root, height=10, bg="#ffffff")
        self.output_box.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Visual indicator for quantum process
        self.visual_frame = tk.Label(self.root, text="Quantum Key Exchange Simulation Status", bg="#f4f4f4", font=("Arial", 10, "italic"))
        self.visual_frame.pack(pady=5)
        self.visual_text = tk.StringVar(value="Idle")
        self.visual_label = tk.Label(self.root, textvariable=self.visual_text, bg="#ffffcc", width=80)
        self.visual_label.pack(pady=5)

        # Set visibility of GUI sections based on selected mode
        self.update_mode()

    def update_mode(self):
        # Update GUI layout based on selected operation mode
        if self.mode_var.get() == "encrypt":
            self.key_frame.pack_forget()
            self.copy_button.pack_forget()
            self.save_key_button.pack_forget()
        else:
            self.key_frame.pack(pady=5)
            self.copy_button.pack_forget()
            self.save_key_button.pack_forget()

    def simulate_quantum_process(self):
        # Simulate quantum key exchange visually
        steps = [
            "Initializing quantum channel...",
            "Alice is generating random bits...",
            "Bob is choosing bases...",
            "Qubits are being sent over the channel...",
            "Bob measures the qubits...",
            "Alice and Bob compare bases...",
            "Final key is extracted from matching bases.",
            "Key used to derive AES-256 key...",
            "Encryption process complete."
        ]
        for step in steps:
            self.visual_text.set(step)
            self.root.update()
            time.sleep(0.7)
        self.visual_text.set("Idle")

    def select_file(self):
        # Prompt user to select a file from the system
        path = filedialog.askopenfilename()
        if path:
            self.file_path = path
            self.file_label.config(text=os.path.basename(path))

    def import_key_file(self):
        # Allow user to import Key B from a text file
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if path:
            with open(path, "r") as f:
                content = f.read().strip()
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, content)

    def copy_key_b(self):
        # Copy Key B to clipboard
        if self.key_b:
            pyperclip.copy(self.key_b)
            messagebox.showinfo("Copied", "Key B has been copied to clipboard.")

    def save_key_b_to_file(self):
        # Save Key B as a .txt file
        if self.key_b:
            path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
            if path:
                with open(path, "w") as f:
                    f.write(self.key_b)
                messagebox.showinfo("Saved", f"Key B saved to: {path}")

    def run(self):
        # Start encryption or decryption in a separate thread
        if not self.file_path:
            messagebox.showwarning("No file selected", "Please select a file first.")
            return

        self.output_box.delete(1.0, tk.END)
        thread = threading.Thread(target=self.process_file)
        thread.start()

    def process_file(self):
        # Dispatch based on selected mode
        if self.mode_var.get() == "encrypt":
            self.simulate_quantum_process()
            self.encrypt()
        else:
            self.decrypt()

    def encrypt(self):
        # Perform encryption using quantum key and AES
        with open(self.file_path, "rb") as f:
            file_bytes = f.read()

        encrypted_data, key_b = encrypt_file_local(file_bytes, os.path.basename(self.file_path))

        save_path = filedialog.asksaveasfilename(defaultextension=".bb84")
        if not save_path:
            return

        with open(save_path, "w") as f:
            f.write(encrypted_data)

        self.key_b = key_b
        self.output_box.insert(tk.END, f"File successfully encrypted and saved to: {save_path}\n")
        self.output_box.insert(tk.END, f"\nKey B (required for decryption):\n{key_b}\n")
        self.output_box.insert(tk.END, self.recommendations(key_b))

        self.copy_button.pack(pady=2)
        self.save_key_button.pack(pady=2)

    def decrypt(self):
        # Perform decryption using provided Key B
        with open(self.file_path, "r") as f:
            encrypted_base64 = f.read()

        key_b_input = self.key_entry.get().strip()

        if not re.fullmatch(r"[01]+", key_b_input):
            messagebox.showerror("Invalid Key", "Key B must be a binary string (only 0s and 1s).")
            return

        key_b_bits = [int(b) for b in key_b_input]

        data, metadata = decrypt_file_local(encrypted_base64, key_b_bits)
        if data is None:
            self.output_box.insert(tk.END, f"Decryption failed: {metadata}\n")
            return

        filename = metadata.get("original_filename", "decrypted_file")
        ext = metadata.get("extension", "bin")
        save_path = filedialog.asksaveasfilename(defaultextension=f".{ext}", initialfile=filename)
        if not save_path:
            return

        with open(save_path, "wb") as f:
            f.write(data)

        self.output_box.insert(tk.END, f"File successfully decrypted and saved to: {save_path}\n")

    def recommendations(self, key_b):
        # Estimate strength of Key B based on bit balance
        ones = key_b.count('1')
        zeros = key_b.count('0')
        balance = abs(ones - zeros)
        status = "Strong" if balance < len(key_b) * 0.4 else "Weak"
        return f"\nKey B Strength Estimate: {status} (1s: {ones}, 0s: {zeros})\n"

    def download_metrics_pdf(self):
        # Load JSON metrics and export to PDF report
        try:
            with open("bb84_metrics.json", "r") as f:
                metrics = json.load(f)
        except:
            messagebox.showerror("Error", "Metrics file not found.")
            return

        class PDF(FPDF):
            def header(self):
                self.set_font("Arial", "B", 14)
                self.cell(0, 10, "BB84 Metrics Report", ln=True, align="C")

            def chapter_body(self, content_dict):
                self.set_font("Arial", "", 11)
                for key, value in content_dict.items():
                    self.cell(0, 10, f"{key}: {value}", ln=True)

        pdf = PDF()
        pdf.add_page()
        pdf.chapter_body(metrics)

        save_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
        if save_path:
            pdf.output(save_path)
            messagebox.showinfo("Saved", f"PDF report saved to: {save_path}")

def main():
    import tkinter as tk
    root = tk.Tk()
    app = BB84App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
