import math
import string

SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?/"
AMBIGUOUS_CHARS = "lIoO01"

# Top 100 most common compromised passwords
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345", "qwerty", "12345678", "111111", "1234567", "123123", "1234567890",
    "monkey", "letmein", "admin", "admin123", "password123", "shadow", "superman", "princess", "iloveyou", "welcome",
    "sunshine", "football", "charlie", "123321", "654321", "666666", "888888", "qwertyuiop", "secret", "killer", 
    "guitar", "dragon", "joshua", "jessica", "soccer", "michael", "ashley", "hunter", "andrew", "daniel", 
    "yellow", "orange", "purple", "monkey1", "monkey2", "bacon", "cheese", "cookies", "starwars", "pokemon", 
    "mustang", "shadow1", "baseball", "football1", "hacker", "hockey", "hunter1", "jessica1", "joshua1", 
    "keyboard", "master", "rookie", "single", "summer", "winter", "spring", "autumn", "nature", "love123", 
    "happy123", "freedom", "matrix", "oracle", "wizard", "magical", "superman1", "batman", "spiderman", 
    "ironman", "avengers", "wonderwoman", "godzilla", "dinosaur", "monster", "zombie", "vampire", "ghost123", 
    "spooky", "scary", "skeleton", "pumpkin", "hallow", "christ", "jesus", "spirit", "grace"
}

def is_common_password(password):
    """
    Checks if a password is a common compromised one or has very simple repetition.
    """
    pwd_lower = password.lower()
    if pwd_lower in COMMON_PASSWORDS:
        return True
    if len(password) > 0 and len(set(password)) == 1:
        return True
    return False

def calculate_entropy(password, mode="character", char_pool_size=None, words_count=None, pattern=None, custom_specials=SPECIAL_CHARS):
    """
    Calculates Shannon entropy (in bits) based on search space.
    """
    if not password:
        return 0.0

    length = len(password)
    
    if mode == "passphrase":
        words = words_count if words_count is not None else len(password.replace(" ", "-").split("-"))
        return float(words * 10.0)  # log2(1024 words) = 10 bits per word
        
    elif mode == "pronounceable":
        letters_only = "".join(c for c in password if c.isalpha())
        base_length = len(letters_only)
        consonants_count = math.ceil(base_length / 2)
        vowels_count = math.floor(base_length / 2)
        entropy = consonants_count * math.log2(21) + vowels_count * math.log2(5)
        return float(round(entropy, 2))
        
    elif mode == "pattern":
        if not pattern:
            return 0.0
        entropy = 0.0
        i = 0
        while i < len(pattern):
            if pattern[i] == "?" and i + 1 < len(pattern):
                spec = pattern[i+1]
                if spec == "u":
                    entropy += math.log2(26)
                elif spec == "l":
                    entropy += math.log2(26)
                elif spec == "d":
                    entropy += math.log2(10)
                elif spec == "s":
                    pool_sz = len(custom_specials) if custom_specials else len(SPECIAL_CHARS)
                    entropy += math.log2(pool_sz)
                elif spec == "a":
                    pool_sz = 26 + 26 + 10 + (len(custom_specials) if custom_specials else len(SPECIAL_CHARS))
                    entropy += math.log2(pool_sz)
                i += 2
            else:
                i += 1
        return float(round(entropy, 2))
        
    else:  # "character" mode
        if char_pool_size is None or char_pool_size == 0:
            pool = 0
            if any(c in string.ascii_lowercase for c in password):
                pool += 26
            if any(c in string.ascii_uppercase for c in password):
                pool += 26
            if any(c in string.digits for c in password):
                pool += 10
            # check any special character
            if any(c in SPECIAL_CHARS for c in password):
                pool += len(SPECIAL_CHARS)
            char_pool_size = pool if pool > 0 else 1
            
        entropy = length * math.log2(char_pool_size)
        return float(round(entropy, 2))

def evaluate_strength(password, entropy=None):
    """
    Evaluates password strength based on length, entropy, and compromise lists.
    Returns: (strength_label, strength_color)
    """
    length = len(password)
    if length == 0:
        return "Invalid", "#ff4d4d"
        
    if is_common_password(password):
        return "Compromised / Very Weak", "#ff4d4d"

    if entropy is None:
        entropy = calculate_entropy(password, mode="character")
        
    if entropy < 40:
        return "Very Weak", "#ff4d4d"
    elif entropy < 60:
        return "Weak", "#ff7b72"
    elif entropy < 80:
        return "Medium", "#ffa64d"
    elif entropy < 100:
        return "Strong", "#d4b740"
    else:
        return "Very Strong", "#2eb82e"
