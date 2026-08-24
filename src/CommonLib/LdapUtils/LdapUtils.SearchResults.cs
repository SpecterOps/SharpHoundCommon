using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.DirectoryObjects;
using SharpHoundCommonLib.Enums;

namespace SharpHoundCommonLib {
    public partial class LdapUtils {
        internal static bool ResolveLabel(string objectIdentifier, string distinguishedName, string samAccountType,
            string[] objectClasses, int flags, out Label type) {
            type = Label.Base;
            if (objectIdentifier != null &&
                WellKnownPrincipal.GetWellKnownPrincipal(objectIdentifier, out var principal)) {
                type = principal.ObjectType;
                return true;
            }

            //Override GMSA/MSA account to treat them as users for the graph
            if (objectClasses != null &&
                (objectClasses.Contains(ObjectClass.MSAClass, StringComparer.OrdinalIgnoreCase) ||
                 objectClasses.Contains(ObjectClass.GMSAClass, StringComparer.OrdinalIgnoreCase))) {
                type = Label.User;
                return true;
            }

            if (samAccountType != null) {
                var objectType = Helpers.SamAccountTypeToType(samAccountType);
                if (objectType != Label.Base) {
                    type = objectType;
                    return true;
                }
            }

            if (objectClasses == null || objectClasses.Length == 0) {
                type = Label.Base;
                return false;
            }

            if (objectClasses.Contains(ObjectClass.GroupPolicyContainerClass, StringComparer.OrdinalIgnoreCase))
                type = Label.GPO;
            else if (objectClasses.Contains(ObjectClass.OrganizationalUnitClass, StringComparer.OrdinalIgnoreCase))
                type = Label.OU;
            else if (objectClasses.Contains(ObjectClass.DomainClass, StringComparer.OrdinalIgnoreCase))
                type = Label.Domain;
            else if (objectClasses.Contains(ObjectClass.ContainerClass, StringComparer.OrdinalIgnoreCase))
                type = Label.Container;
            else if (objectClasses.Contains(ObjectClass.ConfigurationClass, StringComparer.OrdinalIgnoreCase))
                type = Label.Configuration;
            else if (objectClasses.Contains(ObjectClass.PKICertificateTemplateClass, StringComparer.OrdinalIgnoreCase))
                type = Label.CertTemplate;
            else if (objectClasses.Contains(ObjectClass.PKIEnrollmentServiceClass, StringComparer.OrdinalIgnoreCase))
                type = Label.EnterpriseCA;
            else if (objectClasses.Contains(ObjectClass.CertificationAuthorityClass,
                         StringComparer.OrdinalIgnoreCase)) {
                if (distinguishedName.IndexOf(DirectoryPaths.RootCALocation, StringComparison.OrdinalIgnoreCase) >= 0)
                    type = Label.RootCA;
                if (distinguishedName.IndexOf(DirectoryPaths.AIACALocation, StringComparison.OrdinalIgnoreCase) >= 0)
                    type = Label.AIACA;
                if (distinguishedName.IndexOf(DirectoryPaths.NTAuthStoreLocation, StringComparison.OrdinalIgnoreCase) >=
                    0)
                    type = Label.NTAuthStore;
            }
            else if (objectClasses.Contains(ObjectClass.OIDContainerClass, StringComparer.OrdinalIgnoreCase)) {
                if (distinguishedName.StartsWith(DirectoryPaths.OIDContainerLocation,
                        StringComparison.OrdinalIgnoreCase))
                    type = Label.Container;
                else if (flags == 2) {
                    type = Label.IssuancePolicy;
                }
            }

            return type != Label.Base;
        }

        public static async Task<(bool Success, ResolvedSearchResult ResolvedResult)> ResolveSearchResult(
            IDirectoryObject directoryObject, ILdapUtils utils) {
            if (!directoryObject.GetObjectIdentifier(out var objectIdentifier)) {
                return (false, default);
            }

            var res = new ResolvedSearchResult {
                ObjectId = objectIdentifier
            };

            //If the object is deleted, we can short circuit the rest of this logic as we don't really care about anything else
            if (directoryObject.IsDeleted()) {
                res.Deleted = true;
                return (true, res);
            }

            if (directoryObject.TryGetLongProperty(LDAPProperties.UserAccountControl, out var rawUac)) {
                var flags = (UacFlags)rawUac;
                if (flags.HasFlag(UacFlags.ServerTrustAccount)) {
                    res.IsDomainController = true;
                    utils.AddDomainController(objectIdentifier);
                }
            }

            string domain;

            if (directoryObject.TryGetDistinguishedName(out var distinguishedName)) {
                domain = Helpers.DistinguishedNameToDomain(distinguishedName);
            }
            else {
                if (objectIdentifier.StartsWith("S-1-5") &&
                    await utils.GetDomainNameFromSid(objectIdentifier) is (true, var domainName)) {
                    domain = domainName;
                }
                else {
                    return (false, default);
                }
            }

            string domainSid;
            var match = SIDRegex.Match(objectIdentifier);
            if (match.Success) {
                domainSid = match.Groups[1].Value;
            }
            else if (await utils.GetDomainSidFromDomainName(domain) is (true, var sid)) {
                domainSid = sid;
            }
            else {
                Logging.Logger.LogWarning("Failed to resolve domain sid for object {Identifier}", objectIdentifier);
                domainSid = null;
            }

            res.Domain = domain;
            res.DomainSid = domainSid;

            if (WellKnownPrincipal.GetWellKnownPrincipal(objectIdentifier, out var wellKnownPrincipal)) {
                res.DisplayName = $"{wellKnownPrincipal.ObjectIdentifier}@{domain}";
                res.ObjectType = wellKnownPrincipal.ObjectType;
                if (await utils.GetWellKnownPrincipal(objectIdentifier, domain) is (true, var convertedPrincipal)) {
                    res.ObjectId = convertedPrincipal.ObjectIdentifier;
                }

                return (true, res);
            }

            res.ObjectType = await ComputeLabel(directoryObject, objectIdentifier, domain, utils);

            directoryObject.TryGetProperty(LDAPProperties.SAMAccountName, out var samAccountName);
            res.DisplayName = ComputeDisplayName(directoryObject, domain, res.ObjectType, samAccountName);
            return (true, res);
        }

        private static async Task<Label> ComputeLabel(IDirectoryObject directoryObject, string objectIdentifier,
            string domain, ILdapUtils utils) {
            if (!directoryObject.GetLabel(out var label)) {
                if (await utils.ResolveIDAndType(objectIdentifier, domain) is (true, var typedPrincipal)) {
                    label = typedPrincipal.ObjectType;
                }
            }

            if (directoryObject.IsMSA() || directoryObject.IsGMSA()) {
                label = Label.User;
            }

            return label;
        }

        private static string ComputeDisplayName(IDirectoryObject directoryObject, string domain, Label label,
            string samAccountName) {
            string displayName;
            switch (label) {
                case Label.User:
                case Label.Group:
                case Label.Base:
                    if (!string.IsNullOrWhiteSpace(samAccountName)) {
                        displayName = $"{samAccountName}@{domain}";
                    }
                    else if (directoryObject.TryGetProperty(LDAPProperties.CanonicalName, out var canonicalName)) {
                        displayName = $"{canonicalName}@{domain}";
                    }
                    else if (directoryObject.TryGetProperty(LDAPProperties.Name, out var name)) {
                        displayName = $"{name}@{domain}";
                    }
                    else {
                        displayName = $"UNKNOWN@{domain}";
                    }
                    break;
                case Label.Computer: {
                        var shortName = samAccountName?.TrimEnd('$');
                        if (directoryObject.TryGetProperty(LDAPProperties.DNSHostName, out var dns)) {
                            displayName = dns;
                        }
                        else if (!string.IsNullOrWhiteSpace(shortName)) {
                            displayName = $"{shortName}.{domain}";
                        }
                        else if (directoryObject.TryGetProperty(LDAPProperties.CanonicalName,
                                       out var canonicalName)) {
                            displayName = $"{canonicalName}.{domain}";
                        }
                        else if (directoryObject.TryGetProperty(LDAPProperties.Name, out var name)) {
                            displayName = $"{name}.{domain}";
                        }
                        else {
                            displayName = $"UNKNOWN.{domain}";
                        }

                        break;
                    }
                case Label.GPO:
                case Label.IssuancePolicy: {
                        if (directoryObject.TryGetProperty(LDAPProperties.DisplayName, out var ldapDisplayName)) {
                            displayName = $"{ldapDisplayName}@{domain}";
                        }
                        else if (directoryObject.TryGetProperty(LDAPProperties.CanonicalName,
                                       out var canonicalName)) {
                            displayName = $"{canonicalName}@{domain}";
                        }
                        else {
                            displayName = $"UNKNOWN@{domain}";
                        }

                        break;
                    }
                case Label.Domain:
                    displayName = domain;
                    break;
                case Label.OU: {
                        if (directoryObject.TryGetProperty(LDAPProperties.Name, out var name)) {
                            displayName = $"{name}@{domain}";
                        }
                        else if (directoryObject.TryGetProperty(LDAPProperties.OU, out var ou)) {
                            displayName = $"{ou}@{domain}";
                        }
                        else {
                            displayName = $"UNKNOWN@{domain}";
                        }

                        break;
                    }
                case Label.Container: {
                        if (directoryObject.TryGetProperty(LDAPProperties.Name, out var name)) {
                            displayName = $"{name}@{domain}";
                        }
                        else if (directoryObject.TryGetProperty(LDAPProperties.CanonicalName,
                                       out var canonicalName)) {
                            displayName = $"{canonicalName}@{domain}";
                        }
                        else {
                            displayName = $"UNKNOWN@{domain}";
                        }

                        break;
                    }
                case Label.Configuration:
                case Label.RootCA:
                case Label.AIACA:
                case Label.NTAuthStore:
                case Label.EnterpriseCA:
                case Label.CertTemplate: {
                        if (directoryObject.TryGetProperty(LDAPProperties.Name, out var name)) {
                            displayName = $"{name}@{domain}";
                        }
                        else {
                            displayName = $"UNKNOWN@{domain}";
                        }

                        break;
                    }
                default:
                    throw new ArgumentOutOfRangeException();
            }

            return displayName.ToUpper();
        }
    }
}
