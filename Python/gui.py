import os
import csv
import json
import tkinter as tk
from tkinter import messagebox, ttk, filedialog
from datetime import datetime

# Import core generation and security analysis methods
from core import (
    SPECIAL_CHARS,
    generate_password,
    generate_passphrase,
    generate_pronounceable,
    generate_pattern
)
from security import (
    calculate_entropy,
    evaluate_strength,
    is_common_password
)

class PasswordGeneratorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("RPA Password Generator")
        self.root.geometry("520x660")
        self.root.resizable(False, False)
        
        # Color Palette - Modern Dark Theme
        self.bg_color = "#1e1e2e"       # Main background
        self.card_color = "#252538"     # Frame/Card background
        self.fg_color = "#cdd6f4"       # Text color
        self.accent_color = "#89b4fa"   # Primary buttons & slider
        self.accent_hover = "#b4befe"   # Accent hover
        self.button_fg = "#11111b"      # Button text
        
        self.root.configure(bg=self.bg_color)
        
        # GUI variables
        # Characters Tab vars
        self.length_var = tk.IntVar(value=16)
        self.upper_var = tk.BooleanVar(value=True)
        self.lower_var = tk.BooleanVar(value=True)
        self.digits_var = tk.BooleanVar(value=True)
        self.special_var = tk.BooleanVar(value=True)
        self.exclude_ambig_var = tk.BooleanVar(value=False)
        self.custom_special_var = tk.StringVar(value=SPECIAL_CHARS)
        
        # Passphrase Tab vars
        self.words_count_var = tk.IntVar(value=4)
        self.separator_var = tk.StringVar(value="-")
        self.capitalize_var = tk.BooleanVar(value=False)

        # Pronounceable Tab vars
        self.pron_length_var = tk.IntVar(value=12)
        self.pron_separator_var = tk.StringVar(value="-")
        self.pron_capitalize_var = tk.BooleanVar(value=False)

        # Custom Pattern Tab vars
        self.pattern_var = tk.StringVar(value="?u?l?l?l?d?d?s")
        
        # General state vars
        self.generated_password = tk.StringVar(value="")
        self.is_password_hidden = tk.BooleanVar(value=False)
        
        # Setup styling
        self.setup_styles()
        
        # Build widgets
        self.create_widgets()
        
        # Initial generation
        self.generate()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        
        # Configure Notebook
        style.configure("TNotebook", background=self.bg_color, borderwidth=0)
        style.configure("TNotebook.Tab", background=self.card_color, foreground=self.fg_color, padding=[10, 5], font=("Segoe UI", 9, "bold"))
        style.map("TNotebook.Tab", background=[("selected", self.accent_color)], foreground=[("selected", self.button_fg)])
        
        # Configure Frame & Label
        style.configure("TFrame", background=self.card_color)
        style.configure("TLabel", background=self.card_color, foreground=self.fg_color, font=("Segoe UI", 9))
        
        # Configure Combobox
        style.configure("TCombobox", fieldbackground="#11111b", background=self.card_color, foreground=self.fg_color, arrowcolor=self.accent_color)

    def create_widgets(self):
        # Title Label
        title_label = tk.Label(
            self.root, 
            text="Secure Password Generator", 
            font=("Segoe UI", 18, "bold"), 
            bg=self.bg_color, 
            fg=self.accent_color
        )
        title_label.pack(pady=(12, 3))
        
        subtitle_label = tk.Label(
            self.root, 
            text="RPA-ready cryptographically secure utility", 
            font=("Segoe UI", 9), 
            bg=self.bg_color, 
            fg="#a6adc8"
        )
        subtitle_label.pack(pady=(0, 8))

        # --- Top Area: Password Display & Strength ---
        display_card = tk.Frame(self.root, bg=self.card_color, bd=0, highlightthickness=0)
        display_card.pack(padx=20, pady=(3, 3), fill="x")
        
        # Password field and Show/Hide toggle
        pass_frame = tk.Frame(display_card, bg="#11111b", height=45, bd=1, relief="solid")
        pass_frame.pack(fill="x", padx=15, pady=(12, 4))
        pass_frame.pack_propagate(False)
        
        self.password_entry = tk.Entry(
            pass_frame, 
            textvariable=self.generated_password, 
            font=("Consolas", 13, "bold"), 
            bg="#11111b", 
            fg=self.fg_color, 
            bd=0, 
            justify="center",
            state="readonly",
            readonlybackground="#11111b"
        )
        self.password_entry.pack(side="left", fill="both", expand=True, padx=(10, 5))
        
        # Show/Hide button
        self.btn_toggle_hide = tk.Button(
            pass_frame,
            text="Hide",
            font=("Segoe UI", 8, "bold"),
            bg="#313244",
            fg=self.fg_color,
            activebackground="#45475a",
            activeforeground=self.fg_color,
            bd=0,
            cursor="hand2",
            padx=10,
            command=self.toggle_password_visibility
        )
        self.btn_toggle_hide.pack(side="right", fill="y", padx=2, pady=2)
        self.is_password_hidden.set(False)

        # Strength Bar, Entropy & Label
        self.strength_frame = tk.Frame(display_card, bg=self.card_color)
        self.strength_frame.pack(fill="x", padx=15, pady=(0, 8))
        
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

        self.entropy_label = tk.Label(
            self.strength_frame,
            text=" (Entropy: 0.0 bits)",
            font=("Segoe UI", 9, "italic"),
            bg=self.card_color,
            fg="#a6adc8"
        )
        self.entropy_label.pack(side="left", padx=(10, 0))

        # --- Middle Area: Notebook (Tabs) ---
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(padx=20, pady=5, fill="both", expand=True)
        
        # Tab 1: Characters
        self.tab_char = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_char, text="Characters")
        self.build_character_tab()
        
        # Tab 2: Passphrase
        self.tab_pass = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_pass, text="Passphrase")
        self.build_passphrase_tab()

        # Tab 3: Pronounceable
        self.tab_pron = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_pron, text="Pronounceable")
        self.build_pronounceable_tab()

        # Tab 4: Custom Pattern
        self.tab_pattern = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_pattern, text="Pattern")
        self.build_pattern_tab()
        
        # Tab 5: History
        self.tab_hist = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_hist, text="Saved History")
        self.build_history_tab()
        
        # Bind tab change event
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)

        # --- Bottom Area: Action Buttons ---
        btn_frame = tk.Frame(self.root, bg=self.bg_color)
        btn_frame.pack(fill="x", padx=20, pady=(5, 5))
        
        # Generate Button
        self.btn_gen = tk.Button(
            btn_frame, 
            text="⚡ Generate Password", 
            font=("Segoe UI", 11, "bold"), 
            bg=self.accent_color, 
            fg=self.button_fg,
            activebackground=self.accent_hover,
            activeforeground=self.button_fg,
            bd=0,
            cursor="hand2",
            pady=6,
            command=self.generate
        )
        self.btn_gen.pack(fill="x", pady=2)
        
        # Copy & Save Frame
        action_frame = tk.Frame(btn_frame, bg=self.bg_color)
        action_frame.pack(fill="x", pady=2)

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
            pady=5,
            command=self.copy_to_clipboard
        )
        self.btn_copy.pack(side="left", fill="x", expand=True, padx=(0, 4))

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
            pady=5,
            command=self.save_to_outputs
        )
        self.btn_save.pack(side="right", fill="x", expand=True, padx=(4, 0))

        # Status Notification Label
        self.status_label = tk.Label(
            self.root, 
            text="", 
            font=("Segoe UI", 9, "italic"), 
            bg=self.bg_color, 
            fg="#a6e3a1"
        )
        self.status_label.pack(pady=(2, 5))

    def build_character_tab(self):
        # Length Slider
        length_label_frame = tk.Frame(self.tab_char, bg=self.card_color)
        length_label_frame.pack(fill="x", padx=15, pady=(10, 0))
        
        tk.Label(
            length_label_frame, 
            text="Password Length", 
            font=("Segoe UI", 9, "bold"), 
            bg=self.card_color, 
            fg=self.fg_color
        ).pack(side="left")
        
        self.length_num_label = tk.Label(
            length_label_frame, 
            text="16", 
            font=("Segoe UI", 9, "bold"), 
            bg=self.card_color, 
            fg=self.accent_color
        )
        self.length_num_label.pack(side="right")

        self.slider = tk.Scale(
            self.tab_char, 
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
        self.slider.pack(fill="x", padx=15, pady=(2, 8))

        # Options Checkboxes Frame
        opts_frame = tk.Frame(self.tab_char, bg=self.card_color)
        opts_frame.pack(fill="x", padx=15, pady=2)

        # Upper, Lower, Digits, Special
        for var, text in [
            (self.upper_var, "Include Uppercase (A-Z)"),
            (self.lower_var, "Include Lowercase (a-z)"),
            (self.digits_var, "Include Numbers (0-9)"),
            (self.special_var, "Include Symbols"),
        ]:
            cb = tk.Checkbutton(
                opts_frame, 
                text=text, 
                variable=var,
                bg=self.card_color,
                fg=self.fg_color,
                selectcolor="#11111b",
                activebackground=self.card_color,
                activeforeground=self.fg_color,
                font=("Segoe UI", 9),
                anchor="w",
                bd=0,
                command=self.generate
            )
            cb.pack(fill="x", pady=1)

        # Custom symbols input
        custom_spec_frame = tk.Frame(opts_frame, bg=self.card_color)
        custom_spec_frame.pack(fill="x", pady=(2, 4))
        tk.Label(custom_spec_frame, text="   Custom Symbols:", bg=self.card_color, fg="#a6adc8", font=("Segoe UI", 8)).pack(side="left")
        
        self.custom_spec_entry = tk.Entry(
            custom_spec_frame,
            textvariable=self.custom_special_var,
            font=("Consolas", 9),
            bg="#11111b",
            fg=self.fg_color,
            bd=1,
            relief="solid",
            insertbackground=self.fg_color
        )
        self.custom_spec_entry.pack(side="left", fill="x", expand=True, padx=(5, 0))
        self.custom_special_var.trace_add("write", lambda *args: self.generate())

        # Exclude Ambiguous
        self.cb_ambig = tk.Checkbutton(
            opts_frame, 
            text="Exclude Ambiguous Characters (l, I, o, 1, 0...)", 
            variable=self.exclude_ambig_var,
            bg=self.card_color,
            fg=self.fg_color,
            selectcolor="#11111b",
            activebackground=self.card_color,
            activeforeground=self.fg_color,
            font=("Segoe UI", 9),
            anchor="w",
            bd=0,
            command=self.generate
        )
        self.cb_ambig.pack(fill="x", pady=(2, 5))

    def build_passphrase_tab(self):
        # Words Slider
        words_label_frame = tk.Frame(self.tab_pass, bg=self.card_color)
        words_label_frame.pack(fill="x", padx=15, pady=(10, 0))
        
        tk.Label(
            words_label_frame, 
            text="Number of Words", 
            font=("Segoe UI", 9, "bold"), 
            bg=self.card_color, 
            fg=self.fg_color
        ).pack(side="left")
        
        self.words_num_label = tk.Label(
            words_label_frame, 
            text="4", 
            font=("Segoe UI", 9, "bold"), 
            bg=self.card_color, 
            fg=self.accent_color
        )
        self.words_num_label.pack(side="right")

        self.words_slider = tk.Scale(
            self.tab_pass, 
            from_=2, 
            to=10, 
            orient="horizontal", 
            variable=self.words_count_var,
            showvalue=False,
            bg=self.card_color,
            fg=self.accent_color,
            troughcolor="#313244",
            activebackground=self.accent_hover,
            bd=0,
            highlightthickness=0,
            command=self.on_words_slider_change
        )
        self.words_slider.pack(fill="x", padx=15, pady=(2, 10))

        # Passphrase options frame
        pass_opts_frame = tk.Frame(self.tab_pass, bg=self.card_color)
        pass_opts_frame.pack(fill="x", padx=15, pady=5)

        # Separator Combobox/Entry
        sep_label_frame = tk.Frame(pass_opts_frame, bg=self.card_color)
        sep_label_frame.pack(fill="x", pady=5)
        
        tk.Label(
            sep_label_frame, 
            text="Separator:", 
            font=("Segoe UI", 9), 
            bg=self.card_color, 
            fg=self.fg_color
        ).pack(side="left")
        
        self.sep_combo = ttk.Combobox(
            sep_label_frame,
            textvariable=self.separator_var,
            values=["-", "_", ".", "/", " ", "None"],
            width=8,
            state="normal"
        )
        self.sep_combo.pack(side="left", padx=10)
        self.sep_combo.bind("<<ComboboxSelected>>", lambda e: self.generate())
        self.separator_var.trace_add("write", lambda *args: self.generate())

        # Capitalize Words
        self.cb_cap = tk.Checkbutton(
            pass_opts_frame, 
            text="Capitalize Words (e.g. Word-Word)", 
            variable=self.capitalize_var,
            bg=self.card_color,
            fg=self.fg_color,
            selectcolor="#11111b",
            activebackground=self.card_color,
            activeforeground=self.fg_color,
            font=("Segoe UI", 9),
            anchor="w",
            bd=0,
            command=self.generate
        )
        self.cb_cap.pack(fill="x", pady=10)

    def build_pronounceable_tab(self):
        # Length Slider
        length_label_frame = tk.Frame(self.tab_pron, bg=self.card_color)
        length_label_frame.pack(fill="x", padx=15, pady=(10, 0))
        
        tk.Label(
            length_label_frame, 
            text="Character Length", 
            font=("Segoe UI", 9, "bold"), 
            bg=self.card_color, 
            fg=self.fg_color
        ).pack(side="left")
        
        self.pron_length_num_label = tk.Label(
            length_label_frame, 
            text="12", 
            font=("Segoe UI", 9, "bold"), 
            bg=self.card_color, 
            fg=self.accent_color
        )
        self.pron_length_num_label.pack(side="right")

        self.pron_slider = tk.Scale(
            self.tab_pron, 
            from_=4, 
            to=32, 
            orient="horizontal", 
            variable=self.pron_length_var,
            showvalue=False,
            bg=self.card_color,
            fg=self.accent_color,
            troughcolor="#313244",
            activebackground=self.accent_hover,
            bd=0,
            highlightthickness=0,
            command=self.on_pron_slider_change
        )
        self.pron_slider.pack(fill="x", padx=15, pady=(2, 10))

        # Options frame
        pron_opts_frame = tk.Frame(self.tab_pron, bg=self.card_color)
        pron_opts_frame.pack(fill="x", padx=15, pady=5)

        # Separator Combobox
        sep_label_frame = tk.Frame(pron_opts_frame, bg=self.card_color)
        sep_label_frame.pack(fill="x", pady=5)
        
        tk.Label(
            sep_label_frame, 
            text="Separator (every 4 chars):", 
            font=("Segoe UI", 9), 
            bg=self.card_color, 
            fg=self.fg_color
        ).pack(side="left")
        
        self.pron_sep_combo = ttk.Combobox(
            sep_label_frame,
            textvariable=self.pron_separator_var,
            values=["-", "_", ".", "None"],
            width=8,
            state="normal"
        )
        self.pron_sep_combo.pack(side="left", padx=10)
        self.pron_sep_combo.bind("<<ComboboxSelected>>", lambda e: self.generate())
        self.pron_separator_var.trace_add("write", lambda *args: self.generate())

        # Capitalize Blocks
        self.cb_pron_cap = tk.Checkbutton(
            pron_opts_frame, 
            text="Capitalize Blocks (e.g. Kavo-Seti)", 
            variable=self.pron_capitalize_var,
            bg=self.card_color,
            fg=self.fg_color,
            selectcolor="#11111b",
            activebackground=self.card_color,
            activeforeground=self.fg_color,
            font=("Segoe UI", 9),
            anchor="w",
            bd=0,
            command=self.generate
        )
        self.cb_pron_cap.pack(fill="x", pady=10)

    def build_pattern_tab(self):
        pattern_opts_frame = tk.Frame(self.tab_pattern, bg=self.card_color)
        pattern_opts_frame.pack(fill="x", padx=15, pady=10)

        tk.Label(
            pattern_opts_frame, 
            text="Enter Pattern Mask:", 
            font=("Segoe UI", 9, "bold"), 
            bg=self.card_color, 
            fg=self.fg_color
        ).pack(anchor="w", pady=(0, 3))

        self.pattern_entry = tk.Entry(
            pattern_opts_frame,
            textvariable=self.pattern_var,
            font=("Consolas", 10, "bold"),
            bg="#11111b",
            fg=self.fg_color,
            bd=1,
            relief="solid",
            insertbackground=self.fg_color
        )
        self.pattern_entry.pack(fill="x", pady=(0, 10))
        self.pattern_var.trace_add("write", lambda *args: self.generate())

        # Guide/Legend Label
        legend_text = (
            "Pattern Guide:\n"
            "  ?u = Uppercase letter (A-Z)       ?l = Lowercase letter (a-z)\n"
            "  ?d = Digit (0-9)                                 ?s = Special character\n"
            "  ?a = Any character from above\n"
            "  Other characters are literals (e.g. hyphens, spaces)\n\n"
            "Example: ?u?l?l?l-?d?d?d?s  =>  Abcd-123!"
        )
        
        tk.Label(
            pattern_opts_frame,
            text=legend_text,
            font=("Segoe UI", 8),
            bg=self.card_color,
            fg="#a6adc8",
            justify="left",
            anchor="w"
        ).pack(fill="x")

    def build_history_tab(self):
        # A listbox to show generated password history
        hist_frame = tk.Frame(self.tab_hist, bg=self.card_color)
        hist_frame.pack(fill="both", expand=True, padx=15, pady=10)

        # Scrollbar and Listbox
        scrollbar = tk.Scrollbar(hist_frame, orient="vertical")
        
        self.history_listbox = tk.Listbox(
            hist_frame,
            yscrollcommand=scrollbar.set,
            bg="#11111b",
            fg=self.fg_color,
            selectbackground=self.accent_color,
            selectforeground=self.button_fg,
            font=("Consolas", 9),
            bd=1,
            relief="solid",
            highlightthickness=0
        )
        
        scrollbar.config(command=self.history_listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.history_listbox.pack(side="left", fill="both", expand=True)

        # Action buttons for history
        hist_actions = tk.Frame(self.tab_hist, bg=self.card_color)
        hist_actions.pack(fill="x", padx=15, pady=(0, 10))

        self.btn_hist_copy = tk.Button(
            hist_actions,
            text="📋 Copy Selected",
            font=("Segoe UI", 8, "bold"),
            bg="#313244",
            fg=self.fg_color,
            activebackground="#45475a",
            activeforeground=self.fg_color,
            bd=0,
            cursor="hand2",
            padx=10,
            pady=4,
            command=self.copy_selected_history
        )
        self.btn_hist_copy.pack(side="left", padx=(0, 5))

        self.btn_hist_refresh = tk.Button(
            hist_actions,
            text="🔄 Refresh",
            font=("Segoe UI", 8, "bold"),
            bg="#313244",
            fg=self.fg_color,
            activebackground="#45475a",
            activeforeground=self.fg_color,
            bd=0,
            cursor="hand2",
            padx=10,
            pady=4,
            command=self.refresh_history
        )
        self.btn_hist_refresh.pack(side="left", padx=5)

        self.btn_hist_export = tk.Button(
            hist_actions,
            text="📤 Export...",
            font=("Segoe UI", 8, "bold"),
            bg="#313244",
            fg=self.fg_color,
            activebackground="#45475a",
            activeforeground=self.fg_color,
            bd=0,
            cursor="hand2",
            padx=10,
            pady=4,
            command=self.export_history_dialog
        )
        self.btn_hist_export.pack(side="left", padx=5)

        self.btn_hist_clear = tk.Button(
            hist_actions,
            text="❌ Clear File",
            font=("Segoe UI", 8, "bold"),
            bg="#313244",
            fg="#f38ba8",
            activebackground="#45475a",
            activeforeground="#f38ba8",
            bd=0,
            cursor="hand2",
            padx=10,
            pady=4,
            command=self.clear_history_file
        )
        self.btn_hist_clear.pack(side="right", padx=(5, 0))

    def toggle_password_visibility(self):
        self.is_password_hidden.set(not self.is_password_hidden.get())
        if self.is_password_hidden.get():
            self.password_entry.config(show="*")
            self.btn_toggle_hide.config(text="Show")
        else:
            self.password_entry.config(show="")
            self.btn_toggle_hide.config(text="Hide")

    def on_slider_change(self, val):
        self.length_num_label.config(text=str(val))
        self.generate()

    def on_words_slider_change(self, val):
        self.words_num_label.config(text=str(val))
        self.generate()

    def on_pron_slider_change(self, val):
        self.pron_length_num_label.config(text=str(val))
        self.generate()

    def on_tab_changed(self, event):
        active_tab = self.notebook.index("current")
        if active_tab in [0, 1, 2, 3]:
            self.generate()
        elif active_tab == 4:
            self.refresh_history()

    def generate(self):
        try:
            active_tab = self.notebook.index("current")
        except tk.TclError:
            active_tab = 0  # Default to characters tab on initialization
            
        try:
            entropy = 0.0
            if active_tab == 0:
                # Character Password
                password = generate_password(
                    length=self.length_var.get(),
                    use_upper=self.upper_var.get(),
                    use_lower=self.lower_var.get(),
                    use_digits=self.digits_var.get(),
                    use_special=self.special_var.get(),
                    exclude_ambiguous=self.exclude_ambig_var.get(),
                    special_chars_pool=self.custom_special_var.get()
                )
                pool = 0
                if self.upper_var.get(): pool += 26
                if self.lower_var.get(): pool += 26
                if self.digits_var.get(): pool += 10
                if self.special_var.get(): 
                    pool += len(self.custom_special_var.get() if self.custom_special_var.get() else SPECIAL_CHARS)
                
                entropy = calculate_entropy(
                    password, 
                    mode="character", 
                    char_pool_size=pool, 
                    custom_specials=self.custom_special_var.get()
                )
            elif active_tab == 1:
                # Passphrase
                sep = self.separator_var.get()
                if sep == "Space":
                    sep = " "
                elif sep == "None":
                    sep = ""
                password = generate_passphrase(
                    words_count=self.words_count_var.get(),
                    separator=sep,
                    capitalize=self.capitalize_var.get()
                )
                entropy = calculate_entropy(
                    password,
                    mode="passphrase",
                    words_count=self.words_count_var.get()
                )
            elif active_tab == 2:
                # Pronounceable
                sep = self.pron_separator_var.get()
                if sep == "None":
                    sep = ""
                password = generate_pronounceable(
                    length=self.pron_length_var.get(),
                    capitalize=self.pron_capitalize_var.get(),
                    separator=sep
                )
                entropy = calculate_entropy(
                    password,
                    mode="pronounceable"
                )
            elif active_tab == 3:
                # Custom Pattern
                password = generate_pattern(
                    pattern=self.pattern_var.get(),
                    special_chars_pool=SPECIAL_CHARS
                )
                entropy = calculate_entropy(
                    password,
                    mode="pattern",
                    pattern=self.pattern_var.get()
                )
            else:
                return # Don't generate on history tab
                
            self.generated_password.set(password)
            
            # Update strength and entropy display
            strength, color = evaluate_strength(password, entropy)
            self.strength_val_label.config(text=strength, fg=color)
            self.entropy_label.config(text=f" (Entropy: {entropy} bits)", fg="#a6adc8")
            
            if is_common_password(password):
                self.status_label.config(text="⚠️ Weak/Compromised password!", fg="#f38ba8")
            else:
                self.status_label.config(text="") # Clear status
        except ValueError as e:
            self.generated_password.set("")
            self.strength_val_label.config(text="Invalid options", fg="#ff4d4d")
            self.entropy_label.config(text=" (Entropy: 0.0 bits)", fg="#a6adc8")
            self.status_label.config(text=str(e), fg="#f38ba8")

    def copy_to_clipboard(self):
        password = self.generated_password.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            self.root.update()
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
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(file_path, "a", encoding="utf-8") as f:
                f.write(f"[{timestamp}] {password}\n")
            
            self.show_status("Saved to Outputs/generated_passwords.txt!")
            if self.notebook.index("current") == 4:
                self.refresh_history()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save password: {str(e)}")

    def refresh_history(self):
        self.history_listbox.delete(0, tk.END)
        
        outputs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Outputs")
        file_path = os.path.join(outputs_dir, "generated_passwords.txt")
        
        if not os.path.exists(file_path):
            self.history_listbox.insert(tk.END, "No saved passwords found.")
            return
            
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            
            lines = lines[-30:]
            lines.reverse()
            
            for line in lines:
                self.history_listbox.insert(tk.END, line.strip())
        except Exception as e:
            self.history_listbox.insert(tk.END, f"Error reading file: {str(e)}")

    def copy_selected_history(self):
        try:
            selection = self.history_listbox.curselection()
            if not selection:
                return
            item = self.history_listbox.get(selection[0])
            
            if "] " in item:
                password = item.split("] ", 1)[1]
            else:
                password = item
                
            if password and password != "No saved passwords found.":
                self.root.clipboard_clear()
                self.root.clipboard_append(password)
                self.root.update()
                self.show_status("Copied selected password to clipboard!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy selected item: {str(e)}")

    def export_history_dialog(self):
        outputs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Outputs")
        file_path = os.path.join(outputs_dir, "generated_passwords.txt")
        
        if not os.path.exists(file_path):
            messagebox.showinfo("Export", "No history available to export.")
            return
            
        dest_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("JSON Files", "*.json"), ("Text Files", "*.txt")],
            title="Export Password History"
        )
        if not dest_path:
            return
            
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                
            records = []
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                if "] " in line:
                    parts = line.split("] ", 1)
                    timestamp = parts[0].replace("[", "")
                    password = parts[1]
                else:
                    timestamp = "Unknown"
                    password = line
                    
                strength, _ = evaluate_strength(password)
                entropy = calculate_entropy(password)
                records.append({
                    "timestamp": timestamp,
                    "password": password,
                    "entropy_bits": entropy,
                    "strength": strength
                })
                
            if dest_path.endswith(".json"):
                with open(dest_path, "w", encoding="utf-8") as f:
                    json.dump(records, f, indent=2)
            elif dest_path.endswith(".csv"):
                with open(dest_path, "w", encoding="utf-8", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Timestamp", "Password", "Entropy (Bits)", "Strength"])
                    for r in records:
                        writer.writerow([r["timestamp"], r["password"], r["entropy_bits"], r["strength"]])
            else:
                with open(dest_path, "w", encoding="utf-8") as f:
                    for r in records:
                        f.write(f"[{r['timestamp']}] {r['password']} (Entropy: {r['entropy_bits']} bits, Strength: {r['strength']})\n")
                        
            messagebox.showinfo("Success", f"History successfully exported to {os.path.basename(dest_path)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export history: {str(e)}")

    def clear_history_file(self):
        if not messagebox.askyesno("Confirm Clear", "Are you sure you want to clear your saved password history file?"):
            return
            
        outputs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Outputs")
        file_path = os.path.join(outputs_dir, "generated_passwords.txt")
        
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                self.show_status("History file cleared!")
                self.refresh_history()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete history file: {str(e)}")

    def show_status(self, message):
        self.status_label.config(text=message, fg="#a6e3a1")
        self.root.after(3000, lambda: self.status_label.config(text=""))
