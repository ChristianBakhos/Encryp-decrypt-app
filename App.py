import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from PIL import Image
from supabase import create_client, Client
import os
from datetime import datetime

# Supabase configuration
SUPABASE_URL = "https://mthtayujwgupawkzsenk.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im10aHRheXVqd2d1cGF3a3pzZW5rIiwicm9sZSI6ImFub24iLCJpYXQiOjE3MzQ2MDUwNzksImV4cCI6MjA1MDE4MTA3OX0.cofzeTx33wAwfqUT74EPEkGOjg-q958KHTYbEqHMv9k"
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

class Steganography:
    """
    A class implementing steganography techniques to hide and extract data within images.
    CopyThis class provides methods for converting data to binary, hiding it within image pixels,
    and later extracting it. It uses the least significant bit (LSB) technique for data hiding.

    Attributes:
        delimiter (str): A string marker used to identify the end of hidden data.
    """
    def __init__(self):
        self.delimiter = "$END$"

    def text_to_binary(self, data):
        """
        Convert text or bytes data to a binary string representation.
        
        Args:
            data (Union[str, bytes]): The data to convert to binary. Can be either a string or bytes.
        
        Returns:
            str: A string of 1's and 0's representing the binary data, including the delimiter.
        """
        if isinstance(data, str):
            binary = ''.join(format(ord(char), '08b') for char in data)
        else:
            binary = ''.join(format(byte, '08b') for byte in data)
        binary += ''.join(format(ord(char), '08b') for char in self.delimiter)
        return binary

    def binary_to_bytes(self, binary):
        """
        Convert a binary string back to bytes.
        
        Args:
            binary (str): A string of 1's and 0's representing binary data.
        
        Returns:
            bytes: The reconstructed bytes from the binary string.
        """
        bytes_data = []
        for i in range(0, len(binary), 8):
            bytes_data.append(int(binary[i:i+8], 2))
        return bytes(bytes_data)

    def modify_pixel(self, pixel, bit):
        """
        Modify the least significant bit of a pixel value to store a bit of data.
        
        Args:
            pixel (int): The original pixel value.
            bit (str): The bit ('0' or '1') to store in the pixel.
        
        Returns:
            int: The modified pixel value with the new least significant bit.
        """
        return (pixel & ~1) | int(bit)

    def get_pixel_bit(self, pixel):
        """
        Extract the least significant bit from a pixel value.
        
        Args:
            pixel (int): The pixel value to extract the bit from.
        
        Returns:
            int: The least significant bit (0 or 1) from the pixel.
        """
        return pixel & 1

    def hide_data(self, cover_image, data):
        """
        Hide data within an image using LSB steganography.
        
        Args:
            cover_image (PIL.Image): The image to hide data in.
            data (Union[str, bytes]): The data to hide in the image.
        
        Returns:
            PIL.Image: A new image containing the hidden data.
        """
        binary_data = self.text_to_binary(data)
        required_pixels = len(binary_data) // len(cover_image.mode) + 1
        pixels = list(cover_image.getdata())

        # Resize image until it can hold the data
        while len(pixels) < required_pixels:
            cover_image = self.resize_image(cover_image, required_pixels)
            pixels = list(cover_image.getdata())  # Update pixels after resizing

        modified_pixels = []
        for i, pixel in enumerate(pixels):
            modified_pixel = list(pixel)
            for j in range(len(cover_image.mode)):
                if i * len(cover_image.mode) + j < len(binary_data):
                    modified_pixel[j] = self.modify_pixel(modified_pixel[j], binary_data[i * len(cover_image.mode) + j])
            modified_pixels.append(tuple(modified_pixel))

        stego_image = Image.new(cover_image.mode, cover_image.size)
        stego_image.putdata(modified_pixels)
        return stego_image

    def resize_image(self, image, required_pixels):
        """
        Resize an image to ensure it can hold the required amount of data.
        
        Args:
            image (PIL.Image): The image to resize.
            required_pixels (int): The number of pixels needed to store the data.
        
        Returns:
            PIL.Image: The resized image.
        """
        current_pixels = image.width * image.height
        scaling_factor = (required_pixels / current_pixels) ** 0.5  # Calculate scaling factor
        new_width = int(image.width * scaling_factor) + 1  # Add 1 to avoid rounding issues
        new_height = int(image.height * scaling_factor) + 1
        return image.resize((new_width, new_height))

    def extract_data(self, stego_image):
        """
        Extract hidden data from a steganographic image.
        
        Args:
            stego_image (PIL.Image): The image containing hidden data.
        
        Returns:
            bytes: The extracted data.
        
        Raises:
            ValueError: If the delimiter is not found in the extracted data.
        """
        pixels = list(stego_image.getdata())
        binary_data = ''.join(str(self.get_pixel_bit(channel)) for pixel in pixels for channel in pixel)

        delimiter_binary = ''.join(format(ord(char), '08b') for char in self.delimiter)
        end_index = binary_data.find(delimiter_binary)

        if end_index == -1:
            raise ValueError("Delimiter not found. Data might be corrupted.")

        return self.binary_to_bytes(binary_data[:end_index])

class SteganographyApp:
    """
    A GUI application for file encryption and steganography using Tkinter.
    CopyThis class provides a complete interface for user authentication, file encryption,
    and decryption using both AES encryption and image steganography. It includes
    user management through Supabase and file metadata storage.

    Attributes:
        root (tk.Tk): The main window of the application.
        stego (Steganography): The steganography implementation instance.
        user_id (str): The current user's ID after authentication.
    """
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Encryption Application")
        self.root.geometry("800x600")

        self.stego = Steganography()
        self.user_id = None

        self.show_login_screen()

    def create_styled_button(self, frame, text, command):
        """
        Create a styled button with consistent appearance.
        
        Args:
            frame (ttk.Frame): The parent frame for the button.
            text (str): The button's display text.
            command (callable): The function to call when the button is clicked.
        
        Returns:
            ttk.Button: A styled button widget.
        """
        return ttk.Button(
            frame,
            text=text,
            command=command,
            style="Rounded.TButton"
        )

    def show_login_screen(self):
        """
        Display the login screen with email and password fields.
        
        Creates and displays a login form with options for both login and registration.
        """
        self.clear_current_screen()

        frame = ttk.Frame(self.root, padding="20", style="TFrame")
        frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        ttk.Label(frame, text="Email:", style="TLabel").grid(row=0, column=0, pady=10, padx=5, sticky=tk.E)
        email_entry = ttk.Entry(frame, width=30)
        email_entry.grid(row=0, column=1, pady=10)

        ttk.Label(frame, text="Password:", style="TLabel").grid(row=1, column=0, pady=10, padx=5, sticky=tk.E)
        password_entry = ttk.Entry(frame, show="*", width=30)
        password_entry.grid(row=1, column=1, pady=10)

        self.create_styled_button(frame, "Login", lambda: self.login(email_entry.get(), password_entry.get())).grid(row=2, column=0, pady=10, padx=5)
        self.create_styled_button(frame, "Register", lambda: self.register(email_entry.get(), password_entry.get())).grid(row=2, column=1, pady=10, padx=5)

    def show_home_screen(self):
        """
        Display the main application screen after successful login.
        
        Shows options for file encryption and decryption.
        """
        self.clear_current_screen()
        frame = ttk.Frame(self.root, padding="20", style="TFrame")
        frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        ttk.Label(frame, text="Welcome!", font=("Helvetica", 16, "bold"), background="#f5f5f5").grid(row=0, column=0, pady=20, columnspan=2)

        self.create_styled_button(frame, "Encrypt File", self.show_encrypt_screen).grid(row=1, column=0, pady=10, padx=5)
        self.create_styled_button(frame, "Decrypt File", self.show_decrypt_screen).grid(row=1, column=1, pady=10, padx=5)

    def show_encrypt_screen(self):
        """
        Display the file encryption interface.
        
        Shows file selection options for the input file and cover image,
        along with encryption controls and progress indication.
        """
        self.clear_current_screen()
        frame = ttk.Frame(self.root, padding="20", style="TFrame")
        frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        ttk.Label(frame, text="Encrypt File", font=("Helvetica", 14, "bold"), background="#f5f5f5").grid(row=0, column=0, pady=20, columnspan=2)
        file_path_var = tk.StringVar()
        image_path_var = tk.StringVar()

        self.create_styled_button(frame, "Select File", lambda: self.select_file(file_path_var)).grid(row=1, column=0, pady=10, padx=5)
        ttk.Label(frame, textvariable=file_path_var, style="TLabel").grid(row=1, column=1, pady=10, padx=5)

        self.create_styled_button(frame, "Select Image", lambda: self.select_file(image_path_var)).grid(row=2, column=0, pady=10, padx=5)
        ttk.Label(frame, textvariable=image_path_var, style="TLabel").grid(row=2, column=1, pady=10, padx=5)

        self.create_styled_button(frame, "Encrypt", lambda: self.encrypt_file_with_progress(file_path_var.get(), image_path_var.get())).grid(row=3, column=0, columnspan=2, pady=10)

        self.create_styled_button(frame, "Back", self.show_home_screen).grid(row=4, column=0, columnspan=2, pady=10)

        self.encrypt_progress = ttk.Progressbar(frame, orient=tk.HORIZONTAL, mode="determinate", length=300)
        self.encrypt_progress.grid(row=5, column=0, columnspan=2, pady=10)

    def show_decrypt_screen(self):
        """
        Display the file decryption interface.
        
        Shows file selection for encrypted images and decryption controls
        with progress indication.
        """
        self.clear_current_screen()
        frame = ttk.Frame(self.root, padding="20", style="TFrame")
        frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        ttk.Label(frame, text="Decrypt File", font=("Helvetica", 14, "bold"), background="#f5f5f5").grid(row=0, column=0, pady=20, columnspan=2)
        file_path_var = tk.StringVar()

        self.create_styled_button(frame, "Select Encrypted Image", lambda: self.select_file(file_path_var)).grid(row=1, column=0, pady=10, padx=5)
        ttk.Label(frame, textvariable=file_path_var, style="TLabel").grid(row=1, column=1, pady=10, padx=5)

        self.create_styled_button(frame, "Decrypt", lambda: self.decrypt_file_with_progress(file_path_var.get())).grid(row=2, column=0, columnspan=2, pady=10)

        self.create_styled_button(frame, "Back", self.show_home_screen).grid(row=3, column=0, columnspan=2, pady=10)

        self.decrypt_progress = ttk.Progressbar(frame, orient=tk.HORIZONTAL, mode="determinate", length=300)
        self.decrypt_progress.grid(row=4, column=0, columnspan=2, pady=10)

    def clear_current_screen(self):
        """
        Remove all widgets from the current screen.
        
        Cleans up the interface before showing a new screen.
        """
        for widget in self.root.winfo_children():
            widget.destroy()

    def select_file(self, path_var):
        """
        Open a file selection dialog and store the selected path.
        
        Args:
            path_var (tk.StringVar): Variable to store the selected file path.
        """
        filename = filedialog.askopenfilename()
        if filename:
            path_var.set(filename)

    def encrypt_file_with_progress(self, file_path, image_path):
        """
        Encrypt a file and update the progress bar.
        
        Args:
            file_path (str): Path to the file to encrypt.
            image_path (str): Path to the cover image.
        """
        try:
            self.encrypt_progress["value"] = 0
            self.root.update_idletasks()

            # Simulate progress
            self.encrypt_file(file_path, image_path)
            self.encrypt_progress["value"] = 100
            self.root.update_idletasks()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_file_with_progress(self, file_path):
        """
        Decrypt a file and update the progress bar.
        
        Args:
            file_path (str): Path to the encrypted image file.
        """
        try:
            self.decrypt_progress["value"] = 0
            self.root.update_idletasks()

            # Simulate progress
            self.decrypt_file(file_path)
            self.decrypt_progress["value"] = 100
            self.root.update_idletasks()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def login(self, email, password):
        """
        Authenticate user with Supabase.
        
        Args:
            email (str): User's email address.
            password (str): User's password.
        """
        try:
            response = supabase.auth.sign_in_with_password({"email": email, "password": password})
            if response:
                self.user_id = response.user.id
                self.show_home_screen()
            else:
                messagebox.showerror("Login Failed", "Invalid credentials.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def register(self, email, password):
        """
        Register a new user with Supabase.
        
        Args:
            email (str): New user's email address.
            password (str): New user's password.
        """
        try:
            response = supabase.auth.sign_up({"email": email, "password": password})
            if response:
                self.user_id = response.user.id
                self.create_user_entry(self.user_id, email)
                messagebox.showinfo("Success", "Registration complete. Please log in.")
            else:
                messagebox.showerror("Registration Failed", "Unable to register.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def create_user_entry(self, user_id, email):
        """
        Create a new user record in the Supabase database.
        
        Args:
            user_id (str): The new user's unique identifier.
            email (str): The user's email address.
        """
        data = {
            "user_id": user_id,
            "email": email
        }
        supabase.table("users").insert(data).execute()

    def encrypt_file(self, file_path, image_path):
        """
        Encrypt a file using AES and hide it in an image.
        
        Args:
            file_path (str): Path to the file to encrypt.
            image_path (str): Path to the cover image.
        """
        try:
            with open(file_path, 'rb') as file:
                data = file.read()

            key = get_random_bytes(32)
            cipher = AES.new(key, AES.MODE_GCM)
            nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(data)

            cover_image = Image.open(image_path)
            encrypted_data = nonce + tag + ciphertext
            stego_image = self.stego.hide_data(cover_image, encrypted_data)

            save_path = filedialog.asksaveasfilename(defaultextension=".png")
            if save_path:
                stego_image.save(save_path)

                self.store_file_metadata(file_path, save_path, nonce, key, tag)
                messagebox.showinfo("Success", "File encrypted successfully!")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_file(self, image_path):
        """
        Extract and decrypt a file from a steganographic image.
        
        Args:
            image_path (str): Path to the encrypted image file.
        """
        try:
            stego_image = Image.open(image_path)
            encrypted_data = self.stego.extract_data(stego_image)

            metadata = self.fetch_file_metadata(image_path)
            key = bytes.fromhex(metadata["key"])
            nonce = bytes.fromhex(metadata["nonce"])
            tag = bytes.fromhex(metadata["tag"])
            original_file_name = metadata['input_filename']  # Get the original file name

            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            ciphertext = encrypted_data[len(nonce) + len(tag):]
            decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)

            # Let the user choose the folder
            save_folder = filedialog.askdirectory(title="Select Folder to Save Decrypted File")
            if save_folder:
                save_path = os.path.join(save_folder, original_file_name)
                with open(save_path, 'wb') as file:
                    file.write(decrypted_data)

                self.done_decryption(image_path)
                messagebox.showinfo("Success", f"File decrypted successfully! Saved to {save_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))


    def done_decryption(self, output_filename):
        """
        Update the file operation record to mark successful decryption.
        
        Args:
            output_filename (str): The name of the decrypted output file.
        """
        supabase.table("fileoperations").update({'decrypted_at': datetime.now().isoformat()}).eq("output_filename", os.path.basename(output_filename)).eq("user_id", self.user_id).execute()

    def store_file_metadata(self, input_filename, output_filename, nonce, key, tag):
        """
        Store encryption metadata in Supabase.
        
        Args:
            input_filename (str): Original file name.
            output_filename (str): Encrypted file name.
            nonce (bytes): AES nonce value.
            key (bytes): Encryption key.
            tag (bytes): Authentication tag.
        """
        input_file_name = os.path.basename(input_filename)  # Extract only the file name
        output_file_name = os.path.basename(output_filename)  # Extract only the file name

        data = {
            "input_filename": input_file_name,
            "output_filename": output_file_name,
            "nonce": nonce.hex(),
            "key": key.hex(),
            "tag": tag.hex(),
            "user_id": self.user_id
        }
        supabase.table("fileoperations").insert(data).execute()


    def fetch_file_metadata(self, input_filename):
        """
        Retrieve encryption metadata from Supabase.
        
        Args:
            input_filename (str): Name of the encrypted file.
        
        Returns:
            dict: File metadata including encryption keys and parameters.
        
        Raises:
            ValueError: If metadata cannot be found or retrieved.
        """
        try:
            response = supabase.table("fileoperations").select("*").eq("output_filename", os.path.basename(input_filename)).eq("user_id", self.user_id).execute()
            if response.data:
                return response.data[0]
            else:
                raise ValueError("No metadata found for the file.")
        except Exception as e:
            raise ValueError("Failed to fetch metadata:", str(e))

if __name__ == "__main__":
    app = SteganographyApp()
    app.root.mainloop()
