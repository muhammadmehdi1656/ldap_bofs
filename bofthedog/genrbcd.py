from impacket.ldap import ldaptypes
import sys

# Create an ALLOW ACE with the specified sid
def create_allow_ace(sid):
    nace = ldaptypes.ACE()
    nace['AceType'] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
    nace['AceFlags'] = 0x00
    acedata = ldaptypes.ACCESS_ALLOWED_ACE()
    acedata['Mask'] = ldaptypes.ACCESS_MASK()
    acedata['Mask']['Mask'] = 983551  # Full control
    acedata['Sid'] = ldaptypes.LDAP_SID()
    acedata['Sid'].fromCanonical(sid)
    nace['Ace'] = acedata
    return nace


def create_empty_sd():
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd['Revision'] = b'\x01'
    sd['Sbz1'] = b'\x00'
    sd['Control'] = 32772
    sd['OwnerSid'] = ldaptypes.LDAP_SID()
    # BUILTIN\Administrators
    sd['OwnerSid'].fromCanonical('S-1-5-32-544')
    sd['GroupSid'] = b''
    sd['Sacl'] = b''
    acl = ldaptypes.ACL()
    acl['AclRevision'] = 4
    acl['Sbz1'] = 0
    acl['Sbz2'] = 0
    acl.aces = []
    sd['Dacl'] = acl
    return sd

def main():
    #test SID
    # get the base SD


    if len(sys.argv) < 2:
        print("Missing target SID. Ex: S-1-5-21-991973810-2284695103-1193895442-1108")
        sys.exit()

    sid = sys.argv[1]
    sd = create_empty_sd()
    sd['Dacl'].aces.append(create_allow_ace(sid))

    print(sd)

main()