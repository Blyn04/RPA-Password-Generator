import argparse
import sys
import os
import json
import csv
import tkinter as tk

# Import modular components
from gui import PasswordGeneratorGUI
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

def main():
    parser = argparse.ArgumentParser(description="Secure RPA Password Generator")
    # Mode selection
    parser.add_argument("--mode", type=str, choices=["character", "passphrase", "pronounceable", "pattern"], default="character",
                        help="Password generation mode (default: character)")
    
    # Character mode options
    parser.add_argument("--length", type=int, default=16, help="Length of password/pronounceable string (default 16)")
    parser.add_argument("--no-upper", action="store_true", help="Exclude uppercase letters")
    parser.add_argument("--no-lower", action="store_true", help="Exclude lowercase letters")
    parser.add_argument("--no-digits", action="store_true", help="Exclude digits")
    parser.add_argument("--no-special", action="store_true", help="Exclude special characters")
    parser.add_argument("--exclude-ambiguous", action="store_true", help="Exclude ambiguous characters (l, I, o, 1, 0...)")
    parser.add_argument("--custom-specials", type=str, default=SPECIAL_CHARS, help="Custom pool of special characters to use")
    
    # Passphrase mode options
    parser.add_argument("--passphrase", action="store_true", help="Shortcut for passphrase mode")
    parser.add_argument("--words", type=int, default=4, help="Number of words in passphrase (default 4)")
    parser.add_argument("--separator", type=str, default="-", help="Separator between words/blocks (default '-')")
    parser.add_argument("--capitalize", action="store_true", help="Capitalize words/blocks")
    
    # Pronounceable mode shortcut
    parser.add_argument("--pronounceable", action="store_true", help="Shortcut for pronounceable mode")

    # Pattern mode option
    parser.add_argument("--pattern", type=str, help="Pattern mask for pattern-based generation (e.g. '?u?l?l?d?d?s')")
    
    # General options
    parser.add_argument("--count", type=int, default=1, help="Number of passwords to generate (default 1)")
    parser.add_argument("--output-file", type=str, help="Save generated password(s) directly to this file path")
    parser.add_argument("--silent", action="store_true", help="Only output the generated password to stdout (ideal for RPA integration)")
    parser.add_argument("--format", type=str, choices=["text", "json", "csv"], default="text", help="Output format for CLI mode (default: text)")
    parser.add_argument("--gui", action="store_true", help="Force starting the graphical interface")
    
    args = parser.parse_args()

    # Determine if GUI should run
    is_cli = (len(sys.argv) > 1 and not args.gui) or (len(sys.argv) == 2 and args.gui is False)

    if not is_cli:
        root = tk.Tk()
        app = PasswordGeneratorGUI(root)
        root.mainloop()
    else:
        try:
            # Determine mode
            mode = args.mode
            if args.passphrase:
                mode = "passphrase"
            elif args.pronounceable:
                mode = "pronounceable"
            elif args.pattern:
                mode = "pattern"

            passwords = []
            for _ in range(args.count):
                if mode == "passphrase":
                    pwd = generate_passphrase(
                        words_count=args.words,
                        separator=args.separator,
                        capitalize=args.capitalize
                    )
                elif mode == "pronounceable":
                    pwd = generate_pronounceable(
                        length=args.length,
                        capitalize=args.capitalize,
                        separator=args.separator
                    )
                elif mode == "pattern":
                    pwd = generate_pattern(
                        pattern=args.pattern,
                        special_chars_pool=args.custom_specials
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
            
            # Format Output
            if args.format == "json":
                output_records = []
                for p in passwords:
                    if mode == "passphrase":
                        ent = calculate_entropy(p, mode="passphrase", words_count=args.words)
                    elif mode == "pronounceable":
                        ent = calculate_entropy(p, mode="pronounceable")
                    elif mode == "pattern":
                        ent = calculate_entropy(p, mode="pattern", pattern=args.pattern, custom_specials=args.custom_specials)
                    else:
                        pool = 0
                        if not args.no_upper: pool += 26
                        if not args.no_lower: pool += 26
                        if not args.no_digits: pool += 10
                        if not args.no_special: pool += len(args.custom_specials if args.custom_specials else SPECIAL_CHARS)
                        ent = calculate_entropy(p, mode="character", char_pool_size=pool, custom_specials=args.custom_specials)
                    
                    strength, _ = evaluate_strength(p, ent)
                    output_records.append({
                        "password": p,
                        "mode": mode,
                        "length": len(p),
                        "entropy_bits": ent,
                        "strength": strength,
                        "compromised": is_common_password(p)
                    })
                result_str = json.dumps(output_records, indent=2)
            elif args.format == "csv":
                import io
                csv_buffer = io.StringIO()
                writer = csv.writer(csv_buffer)
                writer.writerow(["password", "mode", "length", "entropy_bits", "strength", "compromised"])
                for p in passwords:
                    if mode == "passphrase":
                        ent = calculate_entropy(p, mode="passphrase", words_count=args.words)
                    elif mode == "pronounceable":
                        ent = calculate_entropy(p, mode="pronounceable")
                    elif mode == "pattern":
                        ent = calculate_entropy(p, mode="pattern", pattern=args.pattern, custom_specials=args.custom_specials)
                    else:
                        pool = 0
                        if not args.no_upper: pool += 26
                        if not args.no_lower: pool += 26
                        if not args.no_digits: pool += 10
                        if not args.no_special: pool += len(args.custom_specials if args.custom_specials else SPECIAL_CHARS)
                        ent = calculate_entropy(p, mode="character", char_pool_size=pool, custom_specials=args.custom_specials)
                    strength, _ = evaluate_strength(p, ent)
                    writer.writerow([p, mode, len(p), ent, strength, is_common_password(p)])
                result_str = csv_buffer.getvalue()
            else:
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
                if args.format != "text":
                    print(result_str)
                else:
                    print("="*45)
                    print(f"Generated Secure Output(s):")
                    print("="*45)
                    for p in passwords:
                        if mode == "passphrase":
                            ent = calculate_entropy(p, mode="passphrase", words_count=args.words)
                        elif mode == "pronounceable":
                            ent = calculate_entropy(p, mode="pronounceable")
                        elif mode == "pattern":
                            ent = calculate_entropy(p, mode="pattern", pattern=args.pattern, custom_specials=args.custom_specials)
                        else:
                            pool = 0
                            if not args.no_upper: pool += 26
                            if not args.no_lower: pool += 26
                            if not args.no_digits: pool += 10
                            if not args.no_special: pool += len(args.custom_specials if args.custom_specials else SPECIAL_CHARS)
                            ent = calculate_entropy(p, mode="character", char_pool_size=pool, custom_specials=args.custom_specials)
                        strength, _ = evaluate_strength(p, ent)
                        comp_str = " [COMPROMISED]" if is_common_password(p) else ""
                        print(f"{p} (Strength: {strength}, Entropy: {ent} bits){comp_str}")
                    print("="*45)
                    if args.output_file:
                        print(f"Saved to: {args.output_file}")
                        
        except Exception as e:
            sys.stderr.write(f"Error: {str(e)}\n")
            sys.exit(1)

if __name__ == "__main__":
    main()
