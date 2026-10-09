using System;
using System.Linq;
using SharpHoundCommonLib.Enums;

namespace SharpHoundCommonLib.DirectoryObjects;

public static class DirectoryObjectExtensions {
    public static bool IsMSA(this IDirectoryObject directoryObject) {
        if (!directoryObject.TryGetArrayProperty(LDAPProperties.ObjectClass, out var classes)) {
            return false;
        }

        return classes.Contains(ObjectClass.MSAClass, StringComparer.InvariantCultureIgnoreCase);
    }
    
    public static bool IsGMSA(this IDirectoryObject directoryObject) {
        if (!directoryObject.TryGetArrayProperty(LDAPProperties.ObjectClass, out var classes)) {
            return false;
        }

        return classes.Contains(ObjectClass.GMSAClass, StringComparer.InvariantCultureIgnoreCase);
    }
    
    public static bool GetObjectIdentifier(this IDirectoryObject directoryObject, out string objectIdentifier) {
        // Builtin container has a SID (always "S-1-5-32"). We use the ObjectGUID as ID like for other containers 
        if (directoryObject.TryGetArrayProperty(LDAPProperties.ObjectClass, out var objectClasses) &&
            objectClasses.Contains(ObjectClass.BuiltinDomainClass, StringComparer.OrdinalIgnoreCase) &&
            directoryObject.TryGetGuid(out objectIdentifier) && !string.IsNullOrWhiteSpace(objectIdentifier)) {
            return true;
        }

        if (directoryObject.TryGetSecurityIdentifier(out objectIdentifier) && !string.IsNullOrWhiteSpace(objectIdentifier)) {
            return true;
        }

        return directoryObject.TryGetGuid(out objectIdentifier) && !string.IsNullOrWhiteSpace(objectIdentifier);
    }
    
    public static bool GetLabel(this IDirectoryObject directoryObject, out Label type) {
        type = Label.Base;
        if (!directoryObject.GetObjectIdentifier(out var objectIdentifier)) {
            return false;
        }
        
        if (!directoryObject.TryGetLongProperty(LDAPProperties.Flags, out var flags)) {
            flags = 0;
        }

        directoryObject.TryGetDistinguishedName(out var distinguishedName);
        directoryObject.TryGetProperty(LDAPProperties.SAMAccountType, out var samAccountType);
        directoryObject.TryGetArrayProperty(LDAPProperties.ObjectClass, out var objectClasses);

        return LdapUtils.ResolveLabel(objectIdentifier, distinguishedName, samAccountType, objectClasses, (int)flags,
            out type);
    }
    
    public static bool IsDeleted(this IDirectoryObject directoryObject) {
        if (!directoryObject.TryGetProperty(LDAPProperties.IsDeleted, out var deleted)) {
            return false;
        }

        return bool.TryParse(deleted, out var isDeleted) && isDeleted;
    }
    
    public static bool HasLAPS(this IDirectoryObject directoryObject) {
        if (directoryObject.TryGetLongProperty(LDAPProperties.LAPSExpirationTime, out var lapsExpiration) &&
            lapsExpiration > 0) {
            return true;
        }

        if (directoryObject.TryGetLongProperty(LDAPProperties.LegacyLAPSExpirationTime, out var legacyLapsExpiration) &&
            legacyLapsExpiration > 0) {
            return true;
        }

        return false;
    }
}
