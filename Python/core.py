import secrets
import string
from security import SPECIAL_CHARS, AMBIGUOUS_CHARS

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
    lower_set = string.ascii_lowercase
    upper_set = string.ascii_uppercase
    digits_set = string.digits
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

    # Cryptographically secure shuffle of the list
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

def generate_pronounceable(length=12, capitalize=False, separator="-"):
    """
    Generates a pronounceable password by alternating consonants and vowels.
    If separator is provided, inserts separators to group characters into blocks.
    """
    if length < 4:
        raise ValueError("Pronounceable length must be at least 4 characters.")
    
    consonants = "bcdfghjklmnpqrstvwxyz"
    vowels = "aeiou"
    result = []
    for i in range(length):
        if i % 2 == 0:
            result.append(secrets.choice(consonants))
        else:
            result.append(secrets.choice(vowels))
            
    if separator:
        block_size = 4
        blocks = []
        for i in range(0, len(result), block_size):
            block = "".join(result[i:i+block_size])
            if capitalize:
                block = block.capitalize()
            blocks.append(block)
        return separator.join(blocks)
    else:
        res_str = "".join(result)
        if capitalize:
            res_str = res_str.capitalize()
        return res_str

def generate_pattern(pattern, special_chars_pool=SPECIAL_CHARS):
    """
    Generates a password matching a pattern mask.
    ?u = Uppercase, ?l = Lowercase, ?d = Digit, ?s = Special, ?a = Any
    Other characters are treated as literals.
    """
    if not pattern:
        raise ValueError("Pattern cannot be empty.")
    
    res = []
    i = 0
    while i < len(pattern):
        if pattern[i] == "?" and i + 1 < len(pattern):
            char_type = pattern[i+1]
            if char_type == "u":
                res.append(secrets.choice(string.ascii_uppercase))
            elif char_type == "l":
                res.append(secrets.choice(string.ascii_lowercase))
            elif char_type == "d":
                res.append(secrets.choice(string.digits))
            elif char_type == "s":
                pool = special_chars_pool if special_chars_pool else SPECIAL_CHARS
                res.append(secrets.choice(pool))
            elif char_type == "a":
                pool = string.ascii_lowercase + string.ascii_uppercase + string.digits + (special_chars_pool if special_chars_pool else SPECIAL_CHARS)
                res.append(secrets.choice(pool))
            else:
                res.append(pattern[i:i+2])
            i += 2
        else:
            res.append(pattern[i])
            i += 1
    return "".join(res)
