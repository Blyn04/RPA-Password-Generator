import argparse
import sys
import secrets
import string
import tkinter as tk
from tkinter import messagebox, ttk
import os
from datetime import datetime

# Define character sets
LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?/"
AMBIGUOUS_CHARS = "lIoO01"

# Wordlist of exactly 1024 unique English words for secure passphrase generation
WORDLIST = ['about', 'above', 'across', 'actor', 'acute', 'adapt', 'admit', 'adopt', 'adult', 'after', 'again', 'agent', 'agree', 'ahead', 'alarm', 'album', 'alert', 'alike', 'alive', 'allow', 'alone', 'along', 'alter', 'angry', 'ankle', 'apply', 'arena', 'argue', 'arise', 'armor', 'arrow', 'artist', 'asset', 'audio', 'audit', 'avoid', 'award', 'aware', 'awful', 'bacon', 'badge', 'baker', 'basic', 'basin', 'basis', 'basket', 'beach', 'beard', 'beast', 'begin', 'being', 'belly', 'below', 'bench', 'berry', 'birth', 'bison', 'black', 'blade', 'blame', 'blank', 'blast', 'blaze', 'blend', 'blind', 'blink', 'block', 'blond', 'blood', 'bloom', 'blues', 'board', 'boast', 'bobcat', 'bonus', 'boost', 'booth', 'border', 'brain', 'brake', 'brand', 'brass', 'brave', 'bread', 'break', 'breed', 'brick', 'bride', 'brief', 'bring', 'brisk', 'broad', 'broke', 'brook', 'brown', 'brush', 'buddy', 'build', 'built', 'bunch', 'buyer', 'cabin', 'cable', 'camel', 'camera', 'camp', 'canal', 'candy', 'canoe', 'canon', 'canvas', 'canyon', 'cargo', 'carol', 'carry', 'carve', 'catch', 'cater', 'cause', 'cedar', 'cello', 'chain', 'chair', 'chalk', 'champ', 'chaos', 'charm', 'chart', 'chase', 'cheap', 'cheat', 'check', 'cheek', 'cheer', 'cheese', 'chef', 'cherry', 'chest', 'chief', 'child', 'chili', 'chill', 'chime', 'china', 'chirp', 'choir', 'choke', 'chord', 'chore', 'cider', 'cigar', 'civic', 'civil', 'claim', 'clamp', 'clans', 'clash', 'clasp', 'class', 'claw', 'clay', 'clean', 'clear', 'cleft', 'clerk', 'click', 'cliff', 'climb', 'cling', 'cloak', 'clock', 'clone', 'close', 'cloth', 'cloud', 'clove', 'clown', 'clump', 'coach', 'coast', 'cobra', 'cocoa', 'colt', 'comet', 'comic', 'comma', 'conch', 'condo', 'coral', 'couch', 'cough', 'count', 'court', 'cover', 'coyote', 'crab', 'crack', 'craft', 'crane', 'crank', 'crash', 'crate', 'crater', 'crawl', 'crazy', 'cream', 'creed', 'creek', 'creep', 'crest', 'cricket', 'cried', 'crime', 'crisp', 'crook', 'crop', 'cross', 'crowd', 'crown', 'crude', 'cruel', 'crumb', 'crush', 'crust', 'crypt', 'cube', 'cubic', 'curry', 'curse', 'curve', 'cycle', 'cynic', 'daily', 'dairy', 'daisy', 'dance', 'dandy', 'decor', 'delay', 'delta', 'demon', 'denim', 'dense', 'depot', 'depth', 'derby', 'desk', 'deter', 'devil', 'diary', 'digit', 'diner', 'dingo', 'dirty', 'disco', 'ditch', 'diver', 'dizzy', 'dodge', 'dogma', 'doll', 'dolphin', 'donor', 'donut', 'dough', 'doves', 'draft', 'drain', 'drake', 'drama', 'drank', 'draw', 'dream', 'dress', 'dried', 'drift', 'drill', 'drink', 'drive', 'drone', 'drool', 'droop', 'drove', 'drown', 'drum', 'dryer', 'duck', 'duct', 'duet', 'duke', 'dunes', 'dusty', 'duty', 'dwarf', 'dwell', 'eager', 'eagle', 'early', 'earth', 'easel', 'east', 'eaten', 'ebony', 'echo', 'edge', 'eight', 'elbow', 'elder', 'elect', 'elite', 'elk', 'elm', 'elope', 'elude', 'elves', 'ember', 'empty', 'enact', 'enemy', 'enjoy', 'enter', 'entry', 'envoy', 'epoch', 'equal', 'equip', 'erase', 'error', 'essay', 'ethics', 'evict', 'exact', 'exile', 'exist', 'extra', 'fable', 'face', 'fact', 'fade', 'fairy', 'faith', 'fake', 'falcon', 'fall', 'false', 'fame', 'fancy', 'farce', 'farm', 'fatal', 'fate', 'fault', 'fawn', 'fear', 'feast', 'feat', 'feline', 'fence', 'fern', 'ferry', 'fetch', 'fever', 'fiber', 'field', 'fiery', 'fifth', 'fifty', 'fight', 'file', 'fill', 'film', 'filter', 'filth', 'final', 'finch', 'find', 'fine', 'finger', 'finish', 'fir', 'fire', 'first', 'fish', 'fist', 'five', 'fix', 'flack', 'flag', 'flair', 'flake', 'flame', 'flank', 'flare', 'flash', 'flask', 'flat', 'flaw', 'flea', 'fleet', 'flesh', 'flew', 'flick', 'flier', 'fling', 'flint', 'flirt', 'float', 'flock', 'flood', 'floor', 'flora', 'flour', 'flow', 'flown', 'fluid', 'fluke', 'flung', 'flunk', 'flush', 'flute', 'flux', 'flyer', 'foal', 'foam', 'focal', 'focus', 'foggy', 'foil', 'fold', 'folk', 'folly', 'fond', 'food', 'fool', 'foot', 'force', 'forge', 'forget', 'fork', 'form', 'forty', 'forum', 'foss', 'foster', 'found', 'four', 'fowl', 'fox', 'fraction', 'fragile', 'frame', 'frank', 'fraud', 'free', 'freeze', 'fresh', 'fret', 'friar', 'friction', 'friend', 'frill', 'fringe', 'frock', 'frog', 'front', 'frost', 'frown', 'froze', 'fruit', 'fudge', 'fuel', 'full', 'fume', 'fund', 'funny', 'fur', 'fury', 'fuse', 'fuss', 'future', 'gadget', 'gain', 'gala', 'galaxy', 'gale', 'gallop', 'game', 'gamma', 'gander', 'gang', 'garage', 'garden', 'garlic', 'garter', 'garth', 'gas', 'gasp', 'gate', 'gather', 'gauge', 'gave', 'gaze', 'gear', 'geese', 'gel', 'gem', 'gender', 'genre', 'gentle', 'gently', 'genus', 'germ', 'ghost', 'giant', 'giddy', 'gift', 'giggle', 'gild', 'gill', 'gilt', 'gimlet', 'ginger', 'giraffe', 'gird', 'girl', 'girth', 'give', 'given', 'glade', 'gladly', 'glance', 'gland', 'glare', 'glass', 'glaze', 'gleam', 'glean', 'glide', 'glim', 'glint', 'gloat', 'globe', 'gloom', 'glory', 'gloss', 'glove', 'glow', 'glue', 'glyc', 'gnarl', 'gnat', 'gnaw', 'goal', 'goat', 'goblet', 'goblin', 'godly', 'going', 'gold', 'golf', 'golly', 'gong', 'good', 'goose', 'gopher', 'gorge', 'goshawk', 'gospel', 'gossip', 'gotten', 'gouge', 'gourd', 'govern', 'gown', 'grab', 'grace', 'grade', 'graft', 'grain', 'grand', 'grant', 'grape', 'graph', 'grasp', 'grass', 'grate', 'grave', 'gravy', 'gray', 'graze', 'great', 'greed', 'greek', 'green', 'greet', 'grew', 'grey', 'grid', 'grief', 'grill', 'grim', 'grime', 'grimy', 'grin', 'grind', 'grip', 'grit', 'groan', 'grocer', 'grog', 'groom', 'groove', 'grope', 'grotto', 'group', 'grove', 'grow', 'growl', 'grown', 'grudge', 'grunt', 'guard', 'guava', 'guess', 'guest', 'guide', 'guild', 'guile', 'guilt', 'guilty', 'guise', 'guitar', 'gulf', 'gull', 'gully', 'gulp', 'gum', 'gun', 'gurgle', 'gush', 'gust', 'gusto', 'gut', 'gutter', 'guy', 'gym', 'gypsum', 'habit', 'hack', 'haddock', 'haft', 'hag', 'hail', 'hair', 'hale', 'half', 'halibut', 'hall', 'halo', 'halt', 'halve', 'ham', 'hamlet', 'hammer', 'hammock', 'hamper', 'hand', 'handful', 'handle', 'handy', 'hang', 'hangar', 'hanger', 'hank', 'hansom', 'happy', 'harass', 'harbor', 'hard', 'hardship', 'hardy', 'hare', 'harem', 'hark', 'harm', 'harmony', 'harness', 'harp', 'harpoon', 'harpy', 'harrow', 'harry', 'harsh', 'hart', 'harvest', 'has', 'hash', 'hasp', 'haste', 'hasty', 'hat', 'hatch', 'hatchet', 'hate', 'hatred', 'haul', 'haunch', 'haunt', 'have', 'haven', 'havoc', 'hay', 'hazard', 'haze', 'hazel', 'head', 'heading', 'heady', 'heal', 'health', 'heap', 'hear', 'hearse', 'heart', 'hearth', 'hearty', 'heat', 'heater', 'heath', 'heave', 'heaven', 'heavy', 'heck', 'hectic', 'hedge', 'heed', 'heel', 'heifer', 'height', 'heir', 'held', 'helix', 'hello', 'helm', 'helmet', 'help', 'helpful', 'helpless', 'hem', 'hemlock', 'hemp', 'hen', 'hence', 'herald', 'herb', 'herd', 'here', 'heritage', 'hermit', 'hero', 'heroic', 'heron', 'herring', 'hers', 'herself', 'hew', 'hey', 'hickory', 'hid', 'hidden', 'hide', 'high', 'highway', 'hike', 'hiker', 'hill', 'hilly', 'hilt', 'him', 'himself', 'hind', 'hinder', 'hinge', 'hint', 'hip', 'hippo', 'hire', 'his', 'hiss', 'history', 'hit', 'hitch', 'hive', 'hoar', 'hoard', 'hoarse', 'hoary', 'hobby', 'hobo', 'hock', 'hockey', 'hod', 'hoe', 'hog', 'hoist', 'hold', 'holder', 'hole', 'holiday', 'hollow', 'holly', 'holster', 'holy', 'homage', 'home', 'homely', 'homeward', 'hone', 'honest', 'honey', 'hood', 'hoof', 'hook', 'hoop', 'hoot', 'hop', 'hope', 'hopeful', 'horde', 'horizon', 'horn', 'hornet', 'horny', 'horrible', 'horror', 'horse', 'hose', 'hospital', 'host', 'hostage', 'hostel', 'hostile', 'hot', 'hotel', 'hound', 'hour', 'house', 'household', 'hovel', 'hover', 'how', 'however', 'howl', 'hub', 'huddle', 'hue', 'huff', 'hug', 'huge', 'hulk', 'hull', 'hum', 'human', 'humane', 'humble', 'humbug', 'humid', 'humility', 'humor', 'hump', 'humus', 'hunch', 'hundred', 'hung', 'hunger', 'hungry', 'hunt', 'hunter', 'hurdle', 'hurl', 'hurrah', 'hurry', 'hurt', 'husband', 'hush', 'husk', 'husky', 'hustle', 'hut', 'hybrid', 'hydrant', 'hydrogen', 'hyena', 'hygiene', 'hymn', 'hyphen', 'hysteria']

def generate_password(length=12, use_upper=True, use_lower=True, use_digits=True, use_special=True, exclude_ambiguous=False, special_chars_pool=SPECIAL_CHARS):
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
    special_set = special_chars_pool if special_chars_pool else SPECIAL_CHARS

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
    if len(guaranteed) > length:
        guaranteed = guaranteed[:length]
        
    remaining_length = length - len(guaranteed)
    password_list = guaranteed + [secrets.choice(pool) for _ in range(remaining_length)]

    # Cryptographically secure shuffle of the list to hide the placement of guaranteed characters
    secrets.SystemRandom().shuffle(password_list)

    return "".join(password_list)

def generate_passphrase(words_count=4, separator="-", capitalize=False):
    """
    Generates a secure passphrase of words_count words joined by separator.
    """
    if words_count < 2:
        raise ValueError("Passphrase must contain at least 2 words.")
    selected = [secrets.choice(WORDLIST) for _ in range(words_count)]
    if capitalize:
        selected = [w.capitalize() for w in selected]
    return separator.join(selected)

def evaluate_strength(password):
    """
    Evaluates password strength based on length and entropy metrics.
    Supports both character-based passwords and passphrases.
    Returns: (strength_label, strength_color)
    """
    length = len(password)
    if length == 0:
        return "Invalid", "#ff4d4d"
        
    # Check if passphrase-like (long with common separators)
    is_passphrase = length >= 18 and any(sep in password for sep in [" ", "-", "_", ".", "/"])
    
    if is_passphrase:
        if length < 20:
            return "Medium", "#ffa64d"  # Orange
        elif length < 26:
            return "Strong", "#e6e600"  # Yellow
        else:
            return "Very Strong", "#2eb82e"  # Dark Green
            
    has_lower = any(c in LOWERCASE for c in password)
    has_upper = any(c in UPPERCASE for c in password)
    has_digit = any(c in DIGITS for c in password)
    has_special = any(not c.isalnum() for c in password)
    
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
        self.root.geometry("520x620")
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
        style.configure("TNotebook.Tab", background=self.card_color, foreground=self.fg_color, padding=[12, 6], font=("Segoe UI", 9, "bold"))
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
        title_label.pack(pady=(15, 5))
        
        subtitle_label = tk.Label(
            self.root, 
            text="RPA-ready cryptographically secure utility", 
            font=("Segoe UI", 9), 
            bg=self.bg_color, 
            fg="#a6adc8"
        )
        subtitle_label.pack(pady=(0, 10))

        # --- Top Area: Password Display & Strength ---
        display_card = tk.Frame(self.root, bg=self.card_color, bd=0, highlightthickness=0)
        display_card.pack(padx=20, pady=(5, 5), fill="x")
        
        # Password field and Show/Hide toggle
        pass_frame = tk.Frame(display_card, bg="#11111b", height=45, bd=1, relief="solid")
        pass_frame.pack(fill="x", padx=15, pady=(15, 5))
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

        # Strength Bar & Label
        self.strength_frame = tk.Frame(display_card, bg=self.card_color)
        self.strength_frame.pack(fill="x", padx=15, pady=(0, 10))
        
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
        
        # Tab 3: History
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
        words_label_frame.pack(fill="x", padx=15, pady=(15, 0))
        
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
        self.words_slider.pack(fill="x", padx=15, pady=(2, 15))

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

    def on_tab_changed(self, event):
        active_tab = self.notebook.index("current")
        if active_tab == 0 or active_tab == 1:
            self.generate()
        elif active_tab == 2:
            self.refresh_history()

    def generate(self):
        try:
            active_tab = self.notebook.index("current")
        except tk.TclError:
            active_tab = 0  # Default to characters tab on initialization
            
        try:
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
            else:
                return # Don't generate on history tab
                
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
            # If history tab is active, refresh it immediately
            if self.notebook.index("current") == 2:
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
            
            # Show last 30 passwords, reverse to show newest first
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
            
            # Extract password after timestamp
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

def main():
    parser = argparse.ArgumentParser(description="Secure RPA Password Generator")
    # Character mode options
    parser.add_argument("--length", type=int, default=16, help="Length of the password (min 4, default 16)")
    parser.add_argument("--no-upper", action="store_true", help="Exclude uppercase letters")
    parser.add_argument("--no-lower", action="store_true", help="Exclude lowercase letters")
    parser.add_argument("--no-digits", action="store_true", help="Exclude digits")
    parser.add_argument("--no-special", action="store_true", help="Exclude special characters")
    parser.add_argument("--exclude-ambiguous", action="store_true", help="Exclude ambiguous characters (l, I, o, 1, 0...)")
    parser.add_argument("--custom-specials", type=str, default=SPECIAL_CHARS, help="Custom pool of special characters to use")
    
    # Passphrase mode options
    parser.add_argument("--passphrase", action="store_true", help="Generate a memorable passphrase instead of character password")
    parser.add_argument("--words", type=int, default=4, help="Number of words in passphrase (default 4)")
    parser.add_argument("--separator", type=str, default="-", help="Separator between words (default '-')")
    parser.add_argument("--capitalize", action="store_true", help="Capitalize each word in the passphrase")
    
    # General options
    parser.add_argument("--count", type=int, default=1, help="Number of passwords/passphrases to generate (default 1)")
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
                if args.passphrase:
                    pwd = generate_passphrase(
                        words_count=args.words,
                        separator=args.separator,
                        capitalize=args.capitalize
                    )
                else:
                    pwd = generate_password(
                        length=args.length,
                        use_upper=not args.no_upper,
                        use_lower=not args.no_lower,
                        use_digits=not args.no_digits,
                        use_special=not args.no_special,
                        exclude_ambiguous=args.exclude_ambiguous,
                        special_chars_pool=args.custom_specials
                    )
                passwords.append(pwd)
            
            # Handle Output
            result_str = "\n".join(passwords)
            
            if args.output_file:
                out_dir = os.path.dirname(os.path.abspath(args.output_file))
                if out_dir and not os.path.exists(out_dir):
                    os.makedirs(out_dir, exist_ok=True)
                with open(args.output_file, "w", encoding="utf-8") as f:
                    f.write(result_str)
            
            if args.silent:
                sys.stdout.write(result_str)
                sys.stdout.flush()
            else:
                print("="*40)
                print(f"Generated Secure Output(s):")
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
