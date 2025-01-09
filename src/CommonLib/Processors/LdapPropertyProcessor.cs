using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.OutputTypes;

// ReSharper disable StringLiteralTypo

namespace SharpHoundCommonLib.Processors {
    public class LdapPropertyProcessor {
        private static readonly HashSet<string> ReservedAttributes = new();

        static LdapPropertyProcessor() {
            ReservedAttributes.UnionWith(CommonProperties.TypeResolutionProps);
            ReservedAttributes.UnionWith(CommonProperties.BaseQueryProps);
            ReservedAttributes.UnionWith(CommonProperties.GroupResolutionProps);
            ReservedAttributes.UnionWith(CommonProperties.ComputerMethodProps);
            ReservedAttributes.UnionWith(CommonProperties.ACLProps);
            ReservedAttributes.UnionWith(CommonProperties.ObjectPropsProps);
            ReservedAttributes.UnionWith(CommonProperties.ContainerProps);
            ReservedAttributes.UnionWith(CommonProperties.SPNTargetProps);
            ReservedAttributes.UnionWith(CommonProperties.DomainTrustProps);
            ReservedAttributes.UnionWith(CommonProperties.GPOLocalGroupProps);
            ReservedAttributes.UnionWith(CommonProperties.CertAbuseProps);
            ReservedAttributes.Add(LDAPProperties.DSASignature);
        }

        private readonly ILdapUtils _utils;

        public LdapPropertyProcessor(ILdapUtils utils) {
            _utils = utils;
        }

        private static Dictionary<string, object> GetCommonProps(IDirectoryObject entry) {
            var ret = new Dictionary<string, object>();
            if (entry.TryGetProperty(LDAPProperties.Description, out var description)) {
                ret["description"] = description;
            }

            if (entry.TryGetProperty(LDAPProperties.WhenCreated, out var wc)) {
                ret["whencreated"] = Helpers.ConvertTimestampToUnixEpoch(wc);
            }

            return ret;
        }

        /// <summary>
        ///     Reads specific LDAP properties related to Domains
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public async Task<Dictionary<string, object>> ReadDomainProperties(IDirectoryObject entry, string domain) {
            var props = GetCommonProps(entry);

            if (entry.TryGetProperty(LDAPProperties.ExpirePasswordsOnSmartCardOnlyAccounts, out var expirePassword) &&
                bool.TryParse(expirePassword, out var expirePasswordBool)) {
                props.Add("expirepasswordsonsmartcardonlyaccounts", expirePasswordBool);
            }

            if (entry.TryGetLongProperty(LDAPProperties.MachineAccountQuota, out var machineAccountQuota)) {
                props.Add("machineaccountquota", machineAccountQuota);
            }

            if (entry.TryGetLongProperty(LDAPProperties.MinPwdLength, out var minPwdLength)) {
                props.Add("minpwdlength", minPwdLength);
            }

            if (entry.TryGetLongProperty(LDAPProperties.PwdProperties, out var pwdProperties)) {
                props.Add("pwdproperties", pwdProperties);
            }

            if (entry.TryGetLongProperty(LDAPProperties.PwdHistoryLength, out var pwdHistoryLength)) {
                props.Add("pwdhistorylength", pwdHistoryLength);
            }

            if (entry.TryGetLongProperty(LDAPProperties.LockoutThreshold, out var lockoutThreshold)) {
                props.Add("lockoutthreshold", lockoutThreshold);
            }

            if (entry.TryGetLongProperty(LDAPProperties.MinPwdAge, out var minpwdage)) {
                var duration = ConvertNanoDuration(minpwdage);
                if (duration != null) {
                    props.Add("minpwdage", duration);
                }
            }

            if (entry.TryGetLongProperty(LDAPProperties.MaxPwdAge, out var maxpwdage)) {
                var duration = ConvertNanoDuration(maxpwdage);
                if (duration != null) {
                    props.Add("maxpwdage", duration);
                }
            }

            if (entry.TryGetLongProperty(LDAPProperties.LockoutDuration, out var lockoutduration)) {
                var duration = ConvertNanoDuration(lockoutduration);
                if (duration != null) {
                    props.Add("lockoutduration", duration);
                }
            }

            if (entry.TryGetLongProperty(LDAPProperties.LockOutObservationWindow, out var lockoutobservationwindow)) {
                var duration = ConvertNanoDuration(lockoutobservationwindow);
                if (duration != null) {
                    props.Add("lockoutobservationwindow", lockoutobservationwindow);
                }
            }

            if (!entry.TryGetLongProperty(LDAPProperties.DomainFunctionalLevel, out var functionalLevel)) {
                functionalLevel = -1;
            }

            props.Add("functionallevel", FunctionalLevelToString((int)functionalLevel));

            var dn = entry.GetProperty(LDAPProperties.DistinguishedName);
            var dsh = await _utils.GetDSHueristics(domain, dn);
            props.Add("dsheuristics", dsh.DSHeuristics);

            return props;
        }

        /// <summary>
        ///     Converts a numeric representation of a functional level to its appropriate functional level string
        /// </summary>
        /// <param name="level"></param>
        /// <returns></returns>
        public static string FunctionalLevelToString(int level) {
            var functionalLevel = level switch {
                0 => "2000 Mixed/Native",
                1 => "2003 Interim",
                2 => "2003",
                3 => "2008",
                4 => "2008 R2",
                5 => "2012",
                6 => "2012 R2",
                7 => "2016",
                8 => "2025",
                _ => "Unknown"
            };

            return functionalLevel;
        }

        /// <summary>
        ///     Reads specific LDAP properties related to GPOs
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public static Dictionary<string, object> ReadGPOProperties(IDirectoryObject entry) {
            var props = GetCommonProps(entry);
            entry.TryGetProperty(LDAPProperties.GPCFileSYSPath, out var path);
            props.Add("gpcpath", path.ToUpper());
            return props;
        }

        /// <summary>
        ///     Reads specific LDAP properties related to OUs
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public static Dictionary<string, object> ReadOUProperties(IDirectoryObject entry) {
            var props = GetCommonProps(entry);
            return props;
        }

        /// <summary>
        ///     Reads specific LDAP properties related to Groups
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public static Dictionary<string, object> ReadGroupProperties(IDirectoryObject entry) {
            var props = GetCommonProps(entry);
            entry.TryGetLongProperty(LDAPProperties.AdminCount, out var ac);
            props.Add("admincount", ac != 0);
            return props;
        }

        /// <summary>
        ///     Reads specific LDAP properties related to containers
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public static Dictionary<string, object> ReadContainerProperties(IDirectoryObject entry) {
            var props = GetCommonProps(entry);
            return props;
        }

        public Task<UserProperties>
            ReadUserProperties(IDirectoryObject entry, ResolvedSearchResult searchResult) {
            return ReadUserProperties(entry, searchResult.Domain);
        }

        /// <summary>
        ///     Reads specific LDAP properties related to Users
        /// </summary>
        /// <param name="entry"></param>
        /// <param name="domain"></param>
        /// <returns></returns>
        public async Task<UserProperties> ReadUserProperties(IDirectoryObject entry, string domain) {
            var userProps = new UserProperties();
            var props = GetCommonProps(entry);

            var uacFlags = (UacFlags)0;
            if (entry.TryGetLongProperty(LDAPProperties.UserAccountControl, out var uac)) {
                uacFlags = (UacFlags)uac;
            }

            props.Add("sensitive", uacFlags.HasFlag(UacFlags.NotDelegated));
            props.Add("dontreqpreauth", uacFlags.HasFlag(UacFlags.DontReqPreauth));
            props.Add("passwordnotreqd", uacFlags.HasFlag(UacFlags.PasswordNotRequired));
            props.Add("unconstraineddelegation", uacFlags.HasFlag(UacFlags.TrustedForDelegation));
            props.Add("pwdneverexpires", uacFlags.HasFlag(UacFlags.DontExpirePassword));
            props.Add("enabled", !uacFlags.HasFlag(UacFlags.AccountDisable));
            props.Add("trustedtoauth", uacFlags.HasFlag(UacFlags.TrustedToAuthForDelegation));
            props.Add("smartcardrequired", uacFlags.HasFlag(UacFlags.SmartcardRequired));
            props.Add("encryptedtextpwdallowed", uacFlags.HasFlag(UacFlags.EncryptedTextPwdAllowed));
            props.Add("usedeskeyonly", uacFlags.HasFlag(UacFlags.UseDesKeyOnly));
            props.Add("logonscriptenabled", uacFlags.HasFlag(UacFlags.Script));
            props.Add("lockedout", uacFlags.HasFlag(UacFlags.Lockout));
            props.Add("passwordcantchange", uacFlags.HasFlag(UacFlags.PasswordCantChange));
            props.Add("passwordexpired", uacFlags.HasFlag(UacFlags.PasswordExpired));

            userProps.UnconstrainedDelegation = uacFlags.HasFlag(UacFlags.TrustedForDelegation);

            var comps = new List<TypedPrincipal>();
            if (uacFlags.HasFlag(UacFlags.TrustedToAuthForDelegation) &&
                entry.TryGetArrayProperty(LDAPProperties.AllowedToDelegateTo, out var delegates)) {
                props.Add("allowedtodelegate", delegates);

                foreach (var d in delegates) {
                    if (d == null)
                        continue;

                    var resolvedHost = await _utils.ResolveHostToSid(d, domain);
                    if (resolvedHost.Success && resolvedHost.SecurityIdentifier.Contains("S-1"))
                        comps.Add(new TypedPrincipal {
                            ObjectIdentifier = resolvedHost.SecurityIdentifier,
                            ObjectType = Label.Computer
                        });
                }
            }

            userProps.AllowedToDelegate = comps.Distinct().ToArray();

            if (!entry.TryGetProperty(LDAPProperties.LastLogon, out var lastLogon)) {
                lastLogon = null;
            }

            props.Add("lastlogon", Helpers.ConvertFileTimeToUnixEpoch(lastLogon));

            if (!entry.TryGetProperty(LDAPProperties.LastLogonTimestamp, out var lastLogonTimeStamp)) {
                lastLogonTimeStamp = null;
            }

            props.Add("lastlogontimestamp", Helpers.ConvertFileTimeToUnixEpoch(lastLogonTimeStamp));

            if (!entry.TryGetProperty(LDAPProperties.PasswordLastSet, out var passwordLastSet)) {
                passwordLastSet = null;
            }

            props.Add("pwdlastset",
                Helpers.ConvertFileTimeToUnixEpoch(passwordLastSet));
            entry.TryGetArrayProperty(LDAPProperties.ServicePrincipalNames, out var spn);
            props.Add("serviceprincipalnames", spn);
            props.Add("hasspn", spn.Length > 0);
            props.Add("displayname", entry.GetProperty(LDAPProperties.DisplayName));
            props.Add("email", entry.GetProperty(LDAPProperties.Email));
            props.Add("title", entry.GetProperty(LDAPProperties.Title));
            props.Add("homedirectory", entry.GetProperty(LDAPProperties.HomeDirectory));
            props.Add("userpassword", entry.GetProperty(LDAPProperties.UserPassword));
            props.Add("unixpassword", entry.GetProperty(LDAPProperties.UnixUserPassword));
            props.Add("unicodepassword", entry.GetProperty(LDAPProperties.UnicodePassword));
            props.Add("sfupassword", entry.GetProperty(LDAPProperties.MsSFU30Password));
            props.Add("logonscript", entry.GetProperty(LDAPProperties.ScriptPath));
            props.Add("useraccountcontrol", uac);
            props.Add("profilepath", entry.GetProperty(LDAPProperties.ProfilePath));

            entry.TryGetLongProperty(LDAPProperties.AdminCount, out var ac);
            props.Add("admincount", ac != 0);

            var encryptionTypes = ConvertEncryptionTypes(entry.GetProperty(LDAPProperties.SupportedEncryptionTypes));
            props.Add("supportedencryptiontypes", encryptionTypes);

            entry.TryGetByteArrayProperty(LDAPProperties.SIDHistory, out var sh);
            var sidHistoryList = new List<string>();
            var sidHistoryPrincipals = new List<TypedPrincipal>();
            foreach (var sid in sh) {
                string sSid;
                try {
                    sSid = new SecurityIdentifier(sid, 0).Value;
                } catch {
                    continue;
                }

                sidHistoryList.Add(sSid);

                if (await _utils.ResolveIDAndType(sSid, domain) is (true, var res))
                    sidHistoryPrincipals.Add(res);
            }

            userProps.SidHistory = sidHistoryPrincipals.Distinct().ToArray();

            props.Add("sidhistory", sidHistoryList.ToArray());

            userProps.Props = props;

            return userProps;
        }

        public Task<ComputerProperties> ReadComputerProperties(IDirectoryObject entry,
            ResolvedSearchResult searchResult) {
            return ReadComputerProperties(entry, searchResult.Domain);
        }

        /// <summary>
        ///     Reads specific LDAP properties related to Computers
        /// </summary>
        /// <param name="entry"></param>
        /// <param name="domain"></param>
        /// <returns></returns>
        public async Task<ComputerProperties> ReadComputerProperties(IDirectoryObject entry, string domain) {
            var compProps = new ComputerProperties();
            var props = GetCommonProps(entry);

            var flags = (UacFlags)0;
            if (entry.TryGetLongProperty(LDAPProperties.UserAccountControl, out var uac)) {
                flags = (UacFlags)uac;
            }

            props.Add("enabled", !flags.HasFlag(UacFlags.AccountDisable));
            props.Add("unconstraineddelegation", flags.HasFlag(UacFlags.TrustedForDelegation));
            props.Add("trustedtoauth", flags.HasFlag(UacFlags.TrustedToAuthForDelegation));
            props.Add("isdc", flags.HasFlag(UacFlags.ServerTrustAccount));
            props.Add("encryptedtextpwdallowed", flags.HasFlag(UacFlags.EncryptedTextPwdAllowed));
            props.Add("usedeskeyonly", flags.HasFlag(UacFlags.UseDesKeyOnly));
            props.Add("logonscriptenabled", flags.HasFlag(UacFlags.Script));
            props.Add("lockedout", flags.HasFlag(UacFlags.Lockout));
            props.Add("passwordexpired", flags.HasFlag(UacFlags.PasswordExpired));

            compProps.UnconstrainedDelegation = flags.HasFlag(UacFlags.TrustedForDelegation);

            var encryptionTypes = ConvertEncryptionTypes(entry.GetProperty(LDAPProperties.SupportedEncryptionTypes));
            props.Add("supportedencryptiontypes", encryptionTypes);

            var comps = new List<TypedPrincipal>();
            if (flags.HasFlag(UacFlags.TrustedToAuthForDelegation) &&
                entry.TryGetArrayProperty(LDAPProperties.AllowedToDelegateTo, out var delegates)) {
                props.Add("allowedtodelegate", delegates);

                foreach (var d in delegates) {
                    if (d == null)
                        continue;

                    var resolvedHost = await _utils.ResolveHostToSid(d, domain);
                    if (resolvedHost.Success && resolvedHost.SecurityIdentifier.Contains("S-1"))
                        comps.Add(new TypedPrincipal {
                            ObjectIdentifier = resolvedHost.SecurityIdentifier,
                            ObjectType = Label.Computer
                        });
                }
            }

            compProps.AllowedToDelegate = comps.Distinct().ToArray();

            var allowedToActPrincipals = new List<TypedPrincipal>();
            if (entry.TryGetByteProperty(LDAPProperties.AllowedToActOnBehalfOfOtherIdentity, out var rawAllowedToAct)) {
                var sd = _utils.MakeSecurityDescriptor();
                sd.SetSecurityDescriptorBinaryForm(rawAllowedToAct, AccessControlSections.Access);
                foreach (var rule in sd.GetAccessRules(true, true, typeof(SecurityIdentifier))) {
                    if (await _utils.ResolveIDAndType(rule.IdentityReference(), domain) is (true, var res))
                        allowedToActPrincipals.Add(res);
                }
            }

            compProps.AllowedToAct = allowedToActPrincipals.ToArray();

            props.Add("lastlogon", Helpers.ConvertFileTimeToUnixEpoch(entry.GetProperty(LDAPProperties.LastLogon)));
            props.Add("lastlogontimestamp",
                Helpers.ConvertFileTimeToUnixEpoch(entry.GetProperty(LDAPProperties.LastLogonTimestamp)));
            props.Add("pwdlastset",
                Helpers.ConvertFileTimeToUnixEpoch(entry.GetProperty(LDAPProperties.PasswordLastSet)));
            entry.TryGetArrayProperty(LDAPProperties.ServicePrincipalNames, out var spn);
            props.Add("serviceprincipalnames", spn);
            props.Add("email", entry.GetProperty(LDAPProperties.Email));
            props.Add("useraccountcontrol", uac);
            var os = entry.GetProperty(LDAPProperties.OperatingSystem);
            var sp = entry.GetProperty(LDAPProperties.ServicePack);

            if (sp != null) os = $"{os} {sp}";

            props.Add("operatingsystem", os);

            entry.TryGetByteArrayProperty(LDAPProperties.SIDHistory, out var sh);
            var sidHistoryList = new List<string>();
            var sidHistoryPrincipals = new List<TypedPrincipal>();
            foreach (var sid in sh) {
                string sSid;
                try {
                    sSid = new SecurityIdentifier(sid, 0).Value;
                } catch {
                    continue;
                }

                sidHistoryList.Add(sSid);

                if (await _utils.ResolveIDAndType(sSid, domain) is (true, var res))
                    sidHistoryPrincipals.Add(res);
            }

            compProps.SidHistory = sidHistoryPrincipals.ToArray();

            props.Add("sidhistory", sidHistoryList.ToArray());

            var smsaPrincipals = new List<TypedPrincipal>();
            if (entry.TryGetArrayProperty(LDAPProperties.HostServiceAccount, out var hsa)) {
                foreach (var dn in hsa) {
                    if (await _utils.ResolveDistinguishedName(dn) is (true, var resolvedPrincipal))
                        smsaPrincipals.Add(resolvedPrincipal);
                }
            }

            compProps.DumpSMSAPassword = smsaPrincipals.ToArray();

            compProps.Props = props;

            return compProps;
        }

        /// <summary>
        /// Returns the properties associated with the RootCA
        /// </summary>
        /// <param name="entry"></param>
        /// <returns>Returns a dictionary with the common properties of the RootCA</returns>
        public static Dictionary<string, object> ReadRootCAProperties(IDirectoryObject entry) {
            var props = GetCommonProps(entry);

            // Certificate
            if (entry.TryGetByteProperty(LDAPProperties.CACertificate, out var rawCertificate)) {
                var cert = new ParsedCertificate(rawCertificate);
                props.Add("certthumbprint", cert.Thumbprint);
                props.Add("certname", cert.Name);
                props.Add("certchain", cert.Chain);
                props.Add("hasbasicconstraints", cert.HasBasicConstraints);
                props.Add("basicconstraintpathlength", cert.BasicConstraintPathLength);
            }

            return props;
        }

        /// <summary>
        /// Returns the properties associated with the AIACA
        /// </summary>
        /// <param name="entry"></param>
        /// <returns>Returns a dictionary with the common properties and the crosscertificatepair property of the AICA</returns>
        public static Dictionary<string, object> ReadAIACAProperties(IDirectoryObject entry) {
            var props = GetCommonProps(entry);
            entry.TryGetByteArrayProperty(LDAPProperties.CrossCertificatePair, out var crossCertificatePair);
            var hasCrossCertificatePair = crossCertificatePair.Length > 0;

            props.Add("crosscertificatepair", crossCertificatePair);
            props.Add("hascrosscertificatepair", hasCrossCertificatePair);

            // Certificate
            if (entry.TryGetByteProperty(LDAPProperties.CACertificate, out var rawCertificate)) {
                var cert = new ParsedCertificate(rawCertificate);
                props.Add("certthumbprint", cert.Thumbprint);
                props.Add("certname", cert.Name);
                props.Add("certchain", cert.Chain);
                props.Add("hasbasicconstraints", cert.HasBasicConstraints);
                props.Add("basicconstraintpathlength", cert.BasicConstraintPathLength);
            }

            return props;
        }

        public static Dictionary<string, object> ReadEnterpriseCAProperties(IDirectoryObject entry) {
            var props = GetCommonProps(entry);
            if (entry.TryGetLongProperty("flags", out var flags))
                props.Add("flags", (PKICertificateAuthorityFlags)flags);
            props.Add("caname", entry.GetProperty(LDAPProperties.Name));
            props.Add("dnshostname", entry.GetProperty(LDAPProperties.DNSHostName));

            // Certificate
            if (entry.TryGetByteProperty(LDAPProperties.CACertificate, out var rawCertificate)) {
                var cert = new ParsedCertificate(rawCertificate);
                props.Add("certthumbprint", cert.Thumbprint);
                props.Add("certname", cert.Name);
                props.Add("certchain", cert.Chain);
                props.Add("hasbasicconstraints", cert.HasBasicConstraints);
                props.Add("basicconstraintpathlength", cert.BasicConstraintPathLength);
            }

            return props;
        }

        /// <summary>
        /// Returns the properties associated with the NTAuthStore. These properties will only contain common properties
        /// </summary>
        /// <param name="entry"></param>
        /// <returns>Returns a dictionary with the common properties of the NTAuthStore</returns>
        public static Dictionary<string, object> ReadNTAuthStoreProperties(IDirectoryObject entry) {
            var props = GetCommonProps(entry);
            return props;
        }

        /// <summary>
        /// Reads specific LDAP properties related to CertTemplates
        /// </summary>
        /// <param name="entry"></param>
        /// <returns>Returns a dictionary associated with the CertTemplate properties that were read</returns>
        public static Dictionary<string, object> ReadCertTemplateProperties(IDirectoryObject entry) {
            var props = GetCommonProps(entry);

            props.Add("validityperiod", ConvertPKIPeriod(entry.GetByteProperty(LDAPProperties.PKIExpirationPeriod)));
            props.Add("renewalperiod", ConvertPKIPeriod(entry.GetByteProperty(LDAPProperties.PKIOverlappedPeriod)));

            if (entry.TryGetLongProperty(LDAPProperties.TemplateSchemaVersion, out var schemaVersion))
                props.Add("schemaversion", schemaVersion);

            props.Add("displayname", entry.GetProperty(LDAPProperties.DisplayName));
            props.Add("oid", entry.GetProperty(LDAPProperties.CertTemplateOID));

            if (entry.TryGetLongProperty(LDAPProperties.PKIEnrollmentFlag, out var enrollmentFlagsRaw)) {
                var enrollmentFlags = (PKIEnrollmentFlag)enrollmentFlagsRaw;

                props.Add("enrollmentflag", enrollmentFlags);
                props.Add("requiresmanagerapproval", enrollmentFlags.HasFlag(PKIEnrollmentFlag.PEND_ALL_REQUESTS));
                props.Add("nosecurityextension", enrollmentFlags.HasFlag(PKIEnrollmentFlag.NO_SECURITY_EXTENSION));
            }

            if (entry.TryGetLongProperty(LDAPProperties.PKINameFlag, out var nameFlagsRaw)) {
                var nameFlags = (PKICertificateNameFlag)nameFlagsRaw;

                props.Add("certificatenameflag", nameFlags);
                props.Add("enrolleesuppliessubject",
                    nameFlags.HasFlag(PKICertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT));
                props.Add("subjectaltrequireupn",
                    nameFlags.HasFlag(PKICertificateNameFlag.SUBJECT_ALT_REQUIRE_UPN));
                props.Add("subjectaltrequiredns",
                    nameFlags.HasFlag(PKICertificateNameFlag.SUBJECT_ALT_REQUIRE_DNS));
                props.Add("subjectaltrequiredomaindns",
                    nameFlags.HasFlag(PKICertificateNameFlag.SUBJECT_ALT_REQUIRE_DOMAIN_DNS));
                props.Add("subjectaltrequireemail",
                    nameFlags.HasFlag(PKICertificateNameFlag.SUBJECT_ALT_REQUIRE_EMAIL));
                props.Add("subjectaltrequirespn",
                    nameFlags.HasFlag(PKICertificateNameFlag.SUBJECT_ALT_REQUIRE_SPN));
                props.Add("subjectrequireemail",
                    nameFlags.HasFlag(PKICertificateNameFlag.SUBJECT_REQUIRE_EMAIL));
            }

            entry.TryGetArrayProperty(LDAPProperties.ExtendedKeyUsage, out var ekus);
            props.Add("ekus", ekus);
            entry.TryGetArrayProperty(LDAPProperties.CertificateApplicationPolicy,
                out var certificateApplicationPolicy);
            props.Add("certificateapplicationpolicy", certificateApplicationPolicy);

            entry.TryGetArrayProperty(LDAPProperties.CertificatePolicy, out var certificatePolicy);
            props.Add("certificatepolicy", certificatePolicy);

            if (entry.TryGetLongProperty(LDAPProperties.NumSignaturesRequired, out var authorizedSignatures))
                props.Add("authorizedsignatures", authorizedSignatures);

            var hasUseLegacyProvider = false;
            if (entry.TryGetLongProperty(LDAPProperties.PKIPrivateKeyFlag, out var privateKeyFlagsRaw)) {
                var privateKeyFlags = (PKIPrivateKeyFlag)privateKeyFlagsRaw;
                hasUseLegacyProvider = privateKeyFlags.HasFlag(PKIPrivateKeyFlag.USE_LEGACY_PROVIDER);
            }

            entry.TryGetArrayProperty(LDAPProperties.ApplicationPolicies, out var appPolicies);

            props.Add("applicationpolicies",
                ParseCertTemplateApplicationPolicies(appPolicies,
                    (int)schemaVersion, hasUseLegacyProvider));
            entry.TryGetArrayProperty(LDAPProperties.IssuancePolicies, out var issuancePolicies);
            props.Add("issuancepolicies", issuancePolicies);

            // Construct effectiveekus
            var effectiveekus = schemaVersion == 1 & ekus.Length > 0 ? ekus : certificateApplicationPolicy;
            props.Add("effectiveekus", effectiveekus);

            // Construct authenticationenabled
            var authenticationEnabled =
                effectiveekus.Intersect(Helpers.AuthenticationOIDs).Any() | effectiveekus.Length == 0;
            props.Add("authenticationenabled", authenticationEnabled);

            // Construct schannelauthenticationenabled
            var schannelAuthenticationEnabled =
                effectiveekus.Intersect(Helpers.SchannelAuthenticationOIDs).Any() | effectiveekus.Length == 0;
            props.Add("schannelauthenticationenabled", schannelAuthenticationEnabled);

            return props;
        }

        public async Task<IssuancePolicyProperties> ReadIssuancePolicyProperties(IDirectoryObject entry) {
            var ret = new IssuancePolicyProperties();
            var props = GetCommonProps(entry);
            props.Add("displayname", entry.GetProperty(LDAPProperties.DisplayName));
            props.Add("certtemplateoid", entry.GetProperty(LDAPProperties.CertTemplateOID));

            if (entry.TryGetProperty(LDAPProperties.OIDGroupLink, out var link)) {
                if (await _utils.ResolveDistinguishedName(link) is (true, var linkedGroup)) {
                    props.Add("oidgrouplink", linkedGroup.ObjectIdentifier);
                    ret.GroupLink = linkedGroup;
                }
            }

            ret.Props = props;
            return ret;
        }

        /// <summary>
        ///     Attempts to parse all LDAP attributes outside of the ones already collected and converts them to a human readable
        ///     format using a best guess
        /// </summary>
        /// <param name="entry"></param>
        public Dictionary<string, object> ParseAllProperties(IDirectoryObject entry) {
            var props = new Dictionary<string, object>();

            foreach (var property in entry.PropertyNames()) {
                if (ReservedAttributes.Contains(property, StringComparer.OrdinalIgnoreCase))
                    continue;

                var collCount = entry.PropertyCount(property);
                if (collCount == 0)
                    continue;

                if (collCount == 1) {
                    var testString = entry.GetProperty(property);
                    if (!string.IsNullOrEmpty(testString)) {
                        if (property.Equals("badpasswordtime", StringComparison.OrdinalIgnoreCase))
                            props.Add(property, Helpers.ConvertFileTimeToUnixEpoch(testString));
                        else
                            props.Add(property, BestGuessConvert(testString));
                    }
                } else {
                    if (entry.TryGetByteProperty(property, out var testBytes)) {
                        if (testBytes == null || testBytes.Length == 0) {
                            continue;
                        }

                        // SIDs
                        try {
                            var sid = new SecurityIdentifier(testBytes, 0);
                            props.Add(property, sid.Value);
                            continue;
                        } catch {
                            /* Ignore */
                        }

                        // GUIDs
                        try {
                            var guid = new Guid(testBytes);
                            props.Add(property, guid.ToString());
                            continue;
                        } catch {
                            /* Ignore */
                        }
                    }

                    if (entry.TryGetArrayProperty(property, out var arr) && arr.Length > 0) {
                        props.Add(property, arr.Select(BestGuessConvert).ToArray());
                    }
                }
            }

            return props;
        }

        /// <summary>
        ///     Parse CertTemplate attribute msPKI-RA-Application-Policies
        /// </summary>
        /// <param name="applicationPolicies"></param>
        /// <param name="schemaVersion"></param>
        /// <param name="hasUseLegacyProvider"></param>
        private static string[] ParseCertTemplateApplicationPolicies(string[] applicationPolicies, int schemaVersion,
            bool hasUseLegacyProvider) {
            if (applicationPolicies == null
                || applicationPolicies.Length == 0
                || schemaVersion == 1
                || schemaVersion == 2
                || (schemaVersion == 4 && hasUseLegacyProvider)) {
                return applicationPolicies;
            } else {
                // Format: "Name`Type`Value`Name`Type`Value`..."
                // (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/c55ec697-be3f-4117-8316-8895e4399237)
                // Return the Value of Name = "msPKI-RA-Application-Policies" entries
                var entries = applicationPolicies[0].Split('`');
                return Enumerable.Range(0, entries.Length / 3)
                    .Select(i => entries.Skip(i * 3).Take(3).ToArray())
                    .Where(parts => parts.Length == 3 && parts[0].Equals(LDAPProperties.ApplicationPolicies,
                        StringComparison.OrdinalIgnoreCase))
                    .Select(parts => parts[2])
                    .ToArray();
            }
        }

        /// <summary>
        ///     Does a best guess conversion of the property to a type useable by the UI
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        private static object BestGuessConvert(string value) {
            //Parse boolean values
            if (bool.TryParse(value, out var boolResult)) return boolResult;

            //A string ending with 0Z is likely a timestamp
            if (value.EndsWith("0Z")) return Helpers.ConvertTimestampToUnixEpoch(value);

            //This string corresponds to the max int, and is usually set in accountexpires
            if (value == "9223372036854775807") return -1;

            //Try parsing as an int
            if (int.TryParse(value, out var num)) return num;

            // If we have binary unicode, encode it
            foreach (char c in value) {
                if (char.IsControl(c)) return System.Text.Encoding.UTF8.GetBytes(value);
            }

            //Just return the property as a string
            return value;
        }

        private static List<string> ConvertEncryptionTypes(string encryptionTypes) {
            if (encryptionTypes == null) {
                return null;
            }

            int encryptionTypesInt = Int32.Parse(encryptionTypes);
            List<string> supportedEncryptionTypes = new List<string>();
            if (encryptionTypesInt == 0) {
                supportedEncryptionTypes.Add("Not defined");
            }

            if ((encryptionTypesInt & KerberosEncryptionTypes.DES_CBC_CRC) == KerberosEncryptionTypes.DES_CBC_CRC) {
                supportedEncryptionTypes.Add("DES-CBC-CRC");
            }

            if ((encryptionTypesInt & KerberosEncryptionTypes.DES_CBC_MD5) == KerberosEncryptionTypes.DES_CBC_MD5) {
                supportedEncryptionTypes.Add("DES-CBC-MD5");
            }

            if ((encryptionTypesInt & KerberosEncryptionTypes.RC4_HMAC_MD5) == KerberosEncryptionTypes.RC4_HMAC_MD5) {
                supportedEncryptionTypes.Add("RC4-HMAC-MD5");
            }

            if ((encryptionTypesInt & KerberosEncryptionTypes.AES128_CTS_HMAC_SHA1_96) ==
                KerberosEncryptionTypes.AES128_CTS_HMAC_SHA1_96) {
                supportedEncryptionTypes.Add("AES128-CTS-HMAC-SHA1-96");
            }

            if ((encryptionTypesInt & KerberosEncryptionTypes.AES256_CTS_HMAC_SHA1_96) ==
                KerberosEncryptionTypes.AES256_CTS_HMAC_SHA1_96) {
                supportedEncryptionTypes.Add("AES256-CTS-HMAC-SHA1-96");
            }

            return supportedEncryptionTypes;
        }

        private static string ConvertNanoDuration(long duration) {
            // In case duration is long.MinValue, Math.Abs will overflow.  Value represents Forever or Never
            if (duration == long.MinValue) {
                return "Forever";
                // And if the value is positive, it indicates an error code
            } else if (duration > 0) {
                return null;
            }

            // duration is in 100-nanosecond intervals
            // Convert it to TimeSpan (which uses 1 tick = 100 nanoseconds)
            TimeSpan durationSpan = TimeSpan.FromTicks(Math.Abs(duration));

            // Create a list to hold non-zero time components
            List<string> timeComponents = new List<string>();

            // Add each time component if it's greater than zero
            if (durationSpan.Days > 0) {
                timeComponents.Add($"{durationSpan.Days} {(durationSpan.Days == 1 ? "day" : "days")}");
            }

            if (durationSpan.Hours > 0) {
                timeComponents.Add($"{durationSpan.Hours} {(durationSpan.Hours == 1 ? "hour" : "hours")}");
            }

            if (durationSpan.Minutes > 0) {
                timeComponents.Add($"{durationSpan.Minutes} {(durationSpan.Minutes == 1 ? "minute" : "minutes")}");
            }

            if (durationSpan.Seconds > 0) {
                timeComponents.Add($"{durationSpan.Seconds} {(durationSpan.Seconds == 1 ? "second" : "seconds")}");
            }

            // Join the non-zero components into a single readable string
            string readableDuration = string.Join(", ", timeComponents);

            return readableDuration;
        }

        /// <summary>
        ///     Converts PKIExpirationPeriod/PKIOverlappedPeriod attributes to time approximate times
        /// </summary>
        /// <remarks>https://www.sysadmins.lv/blog-en/how-to-convert-pkiexirationperiod-and-pkioverlapperiod-active-directory-attributes.aspx</remarks>
        /// <param name="bytes"></param>
        /// <returns>Returns a string representing the time period associated with the input byte array in a human readable form</returns>
        private static string ConvertPKIPeriod(byte[] bytes) {
            if (bytes == null || bytes.Length == 0)
                return "Unknown";

            try {
                Array.Reverse(bytes);
                var temp = BitConverter.ToString(bytes).Replace("-", "");
                var value = Convert.ToInt64(temp, 16) * -.0000001;

                if (value % 31536000 == 0 && value / 31536000 >= 1) {
                    if (value / 31536000 == 1) return "1 year";

                    return $"{value / 31536000} years";
                }

                if (value % 2592000 == 0 && value / 2592000 >= 1) {
                    if (value / 2592000 == 1) return "1 month";

                    return $"{value / 2592000} months";
                }

                if (value % 604800 == 0 && value / 604800 >= 1) {
                    if (value / 604800 == 1) return "1 week";

                    return $"{value / 604800} weeks";
                }

                if (value % 86400 == 0 && value / 86400 >= 1) {
                    if (value / 86400 == 1) return "1 day";

                    return $"{value / 86400} days";
                }

                if (value % 3600 == 0 && value / 3600 >= 1) {
                    if (value / 3600 == 1) return "1 hour";

                    return $"{value / 3600} hours";
                }

                return "";
            } catch (Exception) {
                return "Unknown";
            }
        }

        [DllImport("Advapi32", SetLastError = false)]
        private static extern bool IsTextUnicode(byte[] buf, int len, ref IsTextUnicodeFlags opt);

        [Flags]
        [SuppressMessage("ReSharper", "UnusedMember.Local")]
        [SuppressMessage("ReSharper", "InconsistentNaming")]
        private enum IsTextUnicodeFlags {
            IS_TEXT_UNICODE_ASCII16 = 0x0001,
            IS_TEXT_UNICODE_REVERSE_ASCII16 = 0x0010,

            IS_TEXT_UNICODE_STATISTICS = 0x0002,
            IS_TEXT_UNICODE_REVERSE_STATISTICS = 0x0020,

            IS_TEXT_UNICODE_CONTROLS = 0x0004,
            IS_TEXT_UNICODE_REVERSE_CONTROLS = 0x0040,

            IS_TEXT_UNICODE_SIGNATURE = 0x0008,
            IS_TEXT_UNICODE_REVERSE_SIGNATURE = 0x0080,

            IS_TEXT_UNICODE_ILLEGAL_CHARS = 0x0100,
            IS_TEXT_UNICODE_ODD_LENGTH = 0x0200,
            IS_TEXT_UNICODE_DBCS_LEADBYTE = 0x0400,
            IS_TEXT_UNICODE_NULL_BYTES = 0x1000,

            IS_TEXT_UNICODE_UNICODE_MASK = 0x000F,
            IS_TEXT_UNICODE_REVERSE_MASK = 0x00F0,
            IS_TEXT_UNICODE_NOT_UNICODE_MASK = 0x0F00,
            IS_TEXT_UNICODE_NOT_ASCII_MASK = 0xF000
        }
    }

    public class ParsedCertificate {
        public string Thumbprint { get; set; }
        public string Name { get; set; }
        public string[] Chain { get; set; }
        public bool HasBasicConstraints { get; set; }
        public int BasicConstraintPathLength { get; set; }

        public ParsedCertificate(byte[] rawCertificate) {
            var parsedCertificate = new X509Certificate2(rawCertificate);
            Thumbprint = parsedCertificate.Thumbprint;
            var name = parsedCertificate.FriendlyName;
            Name = string.IsNullOrEmpty(name) ? Thumbprint : name;

            // Chain
            try {
                var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.Build(parsedCertificate);
                var temp = new List<string>();
                foreach (var cert in chain.ChainElements) temp.Add(cert.Certificate.Thumbprint);
                Chain = temp.ToArray();
            } catch (Exception e) {
                Logging.LogProvider.CreateLogger("ParsedCertificate").LogWarning(e,
                    "Failed to read certificate chain for certificate {Name} with Algo {Algorithm}", name,
                    parsedCertificate.SignatureAlgorithm.FriendlyName);
                Chain = Array.Empty<string>();
            }


            // Extensions
            var extensions = parsedCertificate.Extensions;
            foreach (var extension in extensions) {
                var certificateExtension = new CertificateExtension(extension);
                switch (certificateExtension.Oid.Value) {
                    case CAExtensionTypes.BasicConstraints:
                        var ext = (X509BasicConstraintsExtension)extension;
                        HasBasicConstraints = ext.HasPathLengthConstraint;
                        BasicConstraintPathLength = ext.PathLengthConstraint;
                        break;
                }
            }
        }
    }

    public class UserProperties {
        public Dictionary<string, object> Props { get; set; } = new();
        public TypedPrincipal[] AllowedToDelegate { get; set; } = Array.Empty<TypedPrincipal>();
        public TypedPrincipal[] SidHistory { get; set; } = Array.Empty<TypedPrincipal>();
        public bool UnconstrainedDelegation { get; set; }
    }

    public class ComputerProperties {
        public Dictionary<string, object> Props { get; set; } = new();
        public TypedPrincipal[] AllowedToDelegate { get; set; } = Array.Empty<TypedPrincipal>();
        public TypedPrincipal[] AllowedToAct { get; set; } = Array.Empty<TypedPrincipal>();
        public TypedPrincipal[] SidHistory { get; set; } = Array.Empty<TypedPrincipal>();
        public TypedPrincipal[] DumpSMSAPassword { get; set; } = Array.Empty<TypedPrincipal>();
        public bool UnconstrainedDelegation { get; set; }
    }

    public class IssuancePolicyProperties {
        public Dictionary<string, object> Props { get; set; } = new();
        public TypedPrincipal GroupLink { get; set; } = new TypedPrincipal();
    }
}