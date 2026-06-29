import argparse
import sys
import secrets
import string
import tkinter as tk
from tkinter import messagebox
import os

# Define character sets
LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?/"

# Ambiguous characters to exclude if requested
AMBIGUOUS_CHARS = "lIoO01"

def generate_password(length=12, use_upper=True, use_lower=True, use_digits=True, use_special=True, exclude_ambiguous=False):
    """
    Generates a secure password based on the criteria.
    Uses Python's secrets module for cryptographically secure random numbers.
    """
    if not (use_upper or use_lower or use_digits or use_special):
        raise ValueError("At least one character type must be selected.")
    
    if length < 4:
        raise ValueError("Password length must be at least 4 characters.")

    # Form target character sets
    lower_set = LOWERCASE
    upper_set = UPPERCASE
    digits_set = DIGITS
    special_set = SPECIAL_CHARS

    if exclude_ambiguous:
        lower_set = "".join(c for c in lower_set if c not in AMBIGUOUS_CHARS)
        upper_set = "".join(c for c in upper_set if c not in AMBIGUOUS_CHARS)
        digits_set = "".join(c for c in digits_set if c not in AMBIGUOUS_CHARS)
        special_set = "".join(c for c in special_set if c not in AMBIGUOUS_CHARS)

    # Build pool and guarantee at least one character from each selected category
    pool = ""
    guaranteed = []

    if use_lower:
        if not lower_set:
            raise ValueError("All lowercase characters were excluded as ambiguous.")
        pool += lower_set
        guaranteed.append(secrets.choice(lower_set))
    if use_upper:
        if not upper_set:
            raise ValueError("All uppercase characters were excluded as ambiguous.")
        pool += upper_set
        guaranteed.append(secrets.choice(upper_set))
    if use_digits:
        if not digits_set:
            raise ValueError("All digits were excluded as ambiguous.")
        pool += digits_set
        guaranteed.append(secrets.choice(digits_set))
    if use_special:
        if not special_set:
            raise ValueError("All special characters were excluded as ambiguous.")
        pool += special_set
        guaranteed.append(secrets.choice(special_set))

    # Fill the remaining length with random choices from the pool
    remaining_length = length - len(guaranteed)
    password_list = guaranteed + [secrets.choice(pool) for _ in range(remaining_length)]

    # Cryptographically secure shuffle of the list to hide the placement of guaranteed characters
    secrets.SystemRandom().shuffle(password_list)

    return "".join(password_list)

def evaluate_strength(password):
    """
    Evaluates password strength based on length and entropy metrics.
    Returns: (strength_label, strength_color)
    """
    length = len(password)
    
    has_lower = any(c in LOWERCASE for c in password)
    has_upper = any(c in UPPERCASE for c in password)
    has_digit = any(c in DIGITS for c in password)
    has_special = any(c in SPECIAL_CHARS for c in password)
    
    types_count = sum([has_lower, has_upper, has_digit, has_special])
    
    if length < 8 or types_count < 2:
        return "Weak", "#ff4d4d"  # Red
    elif length < 12 or types_count < 3:
        return "Medium", "#ffa64d"  # Orange
    elif length < 16 or types_count < 4:
        return "Strong", "#e6e600"  # Yellow/Light Green
    else:
        return "Very Strong", "#2eb82e"  # Dark Green

class PasswordGeneratorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("RPA Password Generator")
        self.root.geometry("480x560")
        self.root.resizable(False, False)
        
        # Color Palette - Modern Dark Theme
        self.bg_color = "#1e1e2e"       # Main background
        self.card_color = "#252538"     # Frame/Card background
        self.fg_color = "#cdd6f4"       # Text color
        self.accent_color = "#89b4fa"   # Primary buttons & slider
        self.accent_hover = "#b4befe"   # Accent hover
        self.button_fg = "#11111b"      # Button text
        
        self.root.configure(bg=self.bg_color)
        
        # Set up GUI variables
        self.length_var = tk.IntVar(value=16)
        self.upper_var = tk.BoolVar(value=True)
        self.lower_var = tk.BoolVar(value=True)
        self.digits_var = tk.BoolVar(value=True)
        self.special_var = tk.BoolVar(value=True)
        self.exclude_ambig_var = tk.BoolVar(value=False)
        self.generated_password = tk.StringVar(value="")
        
        self.create_widgets()
        self.generate() # Generate initial password

    def create_widgets(self):
        # Title Label
        title_label = tk.Label(
            self.root, 
            text="Secure Password Generator", 
            font=("Segoe UI", 18, "bold"), 
            bg=self.bg_color, 
            fg=self.accent_color
        )
        title_label.pack(pady=(20, 10))
        
        subtitle_label = tk.Label(
            self.root, 
            text="RPA-ready cryptographically secure utility", 
            font=("Segoe UI", 10), 
            bg=self.bg_color, 
            fg="#a6adc8"
        )
        subtitle_label.pack(pady=(0, 20))

        # Main Card Frame
        card = tk.Frame(self.root, bg=self.card_color, bd=0, highlightthickness=0)
        card.pack(padx=20, pady=10, fill="both", expand=True)

        # Password Display Frame
        pass_frame = tk.Frame(card, bg="#11111b", height=50, bd=1, relief="solid")
        pass_frame.pack(fill="x", padx=15, pady=(15, 10))
        pass_frame.pack_propagate(False)

        self.password_label = tk.Entry(
            pass_frame, 
            textvariable=self.generated_password, 
            font=("Consolas", 14, "bold"), 
            bg="#11111b", 
            fg=self.fg_color, 
            bd=0, 
            justify="center",
            state="readonly",
            readonlybackground="#11111b"
        )
        self.password_label.pack(fill="both", expand=True, padx=10)

        # Strength Bar & Label
        self.strength_frame = tk.Frame(card, bg=self.card_color)
        self.strength_frame.pack(fill="x", padx=15, pady=(0, 15))
        
        self.strength_desc = tk.Label(
            self.strength_frame, 
            text="Strength: ", 
            font=("Segoe UI", 9), 
            bg=self.card_color, 
            fg="#a6adc8"
        )
        self.strength_desc.pack(side="left")
        
        self.strength_val_label = tk.Label(
            self.strength_frame, 
            text="Strong", 
            font=("Segoe UI", 9, "bold"), 
            bg=self.card_color
        )
        self.strength_val_label.pack(side="left")

        # Length Slider
        length_label_frame = tk.Frame(card, bg=self.card_color)
        length_label_frame.pack(fill="x", padx=15, pady=(10, 0))
        
        tk.Label(
            length_label_frame, 
            text="Password Length", 
            font=("Segoe UI", 10, "bold"), 
            bg=self.card_color, 
            fg=self.fg_color
        ).pack(side="left")
        
        self.length_num_label = tk.Label(
            length_label_frame, 
            text="16", 
            font=("Segoe UI", 10, "bold"), 
            bg=self.card_color, 
            fg=self.accent_color
        )
        self.length_num_label.pack(side="right")

        self.slider = tk.Scale(
            card, 
            from_=8, 
            to=64, 
            orient="horizontal", 
            variable=self.length_var,
            showvalue=False,
            bg=self.card_color,
            fg=self.accent_color,
            troughcolor="#313244",
            activebackground=self.accent_hover,
            bd=0,
            highlightthickness=0,
            command=self.on_slider_change
        )
        self.slider.pack(fill="x", padx=15, pady=(5, 15))

        # Options Checkboxes Frame
        opts_frame = tk.Frame(card, bg=self.card_color)
        opts_frame.pack(fill="x", padx=15, pady=5)

        self.cb_upper = tk.Checkbutton(
            opts_frame, 
            text="Include Uppercase (A-Z)", 
            variable=self.upper_var,
            bg=self.card_color,
            fg=self.fg_color,
            selectcolor="#11111b",
            activebackground=self.card_color,
            activeforeground=self.fg_color,
            font=("Segoe UI", 10),
            anchor="w",
            bd=0,
            command=self.generate
        )
        self.cb_upper.pack(fill="x", pady=2)

        self.cb_lower = tk.Checkbutton(
            opts_frame, 
            text="Include Lowercase (a-z)", 
            variable=self.lower_var,
            bg=self.card_color,
            fg=self.fg_color,
            selectcolor="#11111b",
            activebackground=self.card_color,
            activeforeground=self.fg_color,
            font=("Segoe UI", 10),
            anchor="w",
            bd=0,
            command=self.generate
        )
        self.cb_lower.pack(fill="x", pady=2)

        self.cb_digits = tk.Checkbutton(
            opts_frame, 
            text="Include Numbers (0-9)", 
            variable=self.digits_var,
            bg=self.card_color,
            fg=self.fg_color,
            selectcolor="#11111b",
            activebackground=self.card_color,
            activeforeground=self.fg_color,
            font=("Segoe UI", 10),
            anchor="w",
            bd=0,
            command=self.generate
        )
        self.cb_digits.pack(fill="x", pady=2)

        self.cb_special = tk.Checkbutton(
            opts_frame, 
            text="Include Symbols (!@#$...)", 
            variable=self.special_var,
            bg=self.card_color,
            fg=self.fg_color,
            selectcolor="#11111b",
            activebackground=self.card_color,
            activeforeground=self.fg_color,
            font=("Segoe UI", 10),
            anchor="w",
            bd=0,
            command=self.generate
        )
        self.cb_special.pack(fill="x", pady=2)

        self.cb_ambig = tk.Checkbutton(
            opts_frame, 
            text="Exclude Ambiguous Characters (l, I, o, 1, 0...)", 
            variable=self.exclude_ambig_var,
            bg=self.card_color,
            fg=self.fg_color,
            selectcolor="#11111b",
            activebackground=self.card_color,
            activeforeground=self.fg_color,
            font=("Segoe UI", 10),
            anchor="w",
            bd=0,
            command=self.generate
        )
        self.cb_ambig.pack(fill="x", pady=(2, 10))

        # Generate Button
        self.btn_gen = tk.Button(
            card, 
            text="⚡ Generate Password", 
            font=("Segoe UI", 11, "bold"), 
            bg=self.accent_color, 
            fg=self.button_fg,
            activebackground=self.accent_hover,
            activeforeground=self.button_fg,
            bd=0,
            cursor="hand2",
            pady=8,
            command=self.generate
        )
        self.btn_gen.pack(fill="x", padx=15, pady=5)

        # Copy & Save Frame
        action_frame = tk.Frame(card, bg=self.card_color)
        action_frame.pack(fill="x", padx=15, pady=(5, 15))

        self.btn_copy = tk.Button(
            action_frame, 
            text="📋 Copy to Clipboard", 
            font=("Segoe UI", 9, "bold"), 
            bg="#313244", 
            fg=self.fg_color,
            activebackground="#45475a",
            activeforeground=self.fg_color,
            bd=0,
            cursor="hand2",
            pady=6,
            command=self.copy_to_clipboard
        )
        self.btn_copy.pack(side="left", fill="x", expand=True, padx=(0, 5))

        self.btn_save = tk.Button(
            action_frame, 
            text="💾 Save to Outputs", 
            font=("Segoe UI", 9, "bold"), 
            bg="#313244", 
            fg=self.fg_color,
            activebackground="#45475a",
            activeforeground=self.fg_color,
            bd=0,
            cursor="hand2",
            pady=6,
            command=self.save_to_outputs
        )
        self.btn_save.pack(side="right", fill="x", expand=True, padx=(5, 0))

        # Status Notification Label
        self.status_label = tk.Label(
            self.root, 
            text="", 
            font=("Segoe UI", 9, "italic"), 
            bg=self.bg_color, 
            fg="#a6e3a1"
        )
        self.status_label.pack(pady=(5, 15))

    def on_slider_change(self, val):
        self.length_num_label.config(text=str(val))
        self.generate()

    def generate(self):
        try:
            password = generate_password(
                length=self.length_var.get(),
                use_upper=self.upper_var.get(),
                use_lower=self.lower_var.get(),
                use_digits=self.digits_var.get(),
                use_special=self.special_var.get(),
                exclude_ambiguous=self.exclude_ambig_var.get()
            )
            self.generated_password.set(password)
            
            # Update strength
            strength, color = evaluate_strength(password)
            self.strength_val_label.config(text=strength, fg=color)
            self.status_label.config(text="") # Clear status
        except ValueError as e:
            self.generated_password.set("")
            self.strength_val_label.config(text="Invalid options", fg="#ff4d4d")
            self.status_label.config(text=str(e), fg="#f38ba8")

    def copy_to_clipboard(self):
        password = self.generated_password.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            self.root.update() # Keep in clipboard
            self.show_status("Password copied to clipboard!")

    def save_to_outputs(self):
        password = self.generated_password.get()
        if not password:
            return
            
        outputs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Outputs")
        if not os.path.exists(outputs_dir):
            os.makedirs(outputs_dir)
            
        file_path = os.path.join(outputs_dir, "generated_passwords.txt")
        try:
            # Append generated password with timestamp
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(file_path, "a", encoding="utf-8") as f:
                f.write(f"[{timestamp}] {password}\n")
            
            self.show_status(f"Saved to Outputs/generated_passwords.txt!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save password: {str(e)}")

    def show_status(self, message):
        self.status_label.config(text=message, fg="#a6e3a1")
        # Clear status after 3 seconds
        self.root.after(3000, lambda: self.status_label.config(text=""))

def main():
    parser = argparse.ArgumentParser(description="Secure RPA Password Generator")
    parser.add_argument("--length", type=int, default=16, help="Length of the password (min 4, default 16)")
    parser.add_argument("--no-upper", action="store_true", help="Exclude uppercase letters")
    parser.add_argument("--no-lower", action="store_true", help="Exclude lowercase letters")
    parser.add_argument("--no-digits", action="store_true", help="Exclude digits")
    parser.add_argument("--no-special", action="store_true", help="Exclude special characters")
    parser.add_argument("--exclude-ambiguous", action="store_true", help="Exclude ambiguous characters (l, I, o, 1, 0...)")
    parser.add_argument("--count", type=int, default=1, help="Number of passwords to generate (default 1)")
    parser.add_argument("--output-file", type=str, help="Save generated password(s) directly to this file path")
    parser.add_argument("--silent", action="store_true", help="Only output the generated password to stdout (ideal for RPA integration)")
    parser.add_argument("--gui", action="store_true", help="Force starting the graphical interface")
    
    args = parser.parse_args()

    # Determine if GUI should run
    is_cli = len(sys.argv) > 1 and not args.gui

    if not is_cli:
        # Launch GUI
        root = tk.Tk()
        app = PasswordGeneratorGUI(root)
        root.mainloop()
    else:
        # CLI Mode
        try:
            passwords = []
            for _ in range(args.count):
                pwd = generate_password(
                    length=args.length,
                    use_upper=not args.no_upper,
                    use_lower=not args.no_lower,
                    use_digits=not args.no_digits,
                    use_special=not args.no_special,
                    exclude_ambiguous=args.exclude_ambiguous
                )
                passwords.append(pwd)
            
            # Handle Output
            result_str = "\n".join(passwords)
            
            if args.output_file:
                # Ensure directory exists
                out_dir = os.path.dirname(os.path.abspath(args.output_file))
                if out_dir and not os.path.exists(out_dir):
                    os.makedirs(out_dir, exist_ok=True)
                with open(args.output_file, "w", encoding="utf-8") as f:
                    f.write(result_str)
            
            if args.silent:
                # Print raw password to stdout for RPA scripting
                sys.stdout.write(result_str)
                sys.stdout.flush()
            else:
                print("="*40)
                print(f"Generated Password(s) ({args.length} chars):")
                print("="*40)
                for p in passwords:
                    strength, _ = evaluate_strength(p)
                    print(f"{p} (Strength: {strength})")
                print("="*40)
                if args.output_file:
                    print(f"Saved to: {args.output_file}")
                    
        except Exception as e:
            sys.stderr.write(f"Error: {str(e)}\n")
            sys.exit(1)

if __name__ == "__main__":
    main()
