using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.DirectoryObjects;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
using System.Linq;

namespace SharpHoundCommonLib.Processors {
    public class ACLProcessor {
        private static readonly Dictionary<Label, string> BaseGuids;
        private readonly ConcurrentDictionary<string, string> _guidMap = new();
        private readonly ILogger _log;
        private readonly ILdapUtils _utils;
        private readonly ConcurrentHashSet _builtDomainCaches = new(StringComparer.OrdinalIgnoreCase);
        private readonly object _lock = new();

        static ACLProcessor() {
            //Create a dictionary with the base GUIDs of each object type
            BaseGuids = new Dictionary<Label, string> {
                { Label.User, "bf967aba-0de6-11d0-a285-00aa003049e2" },
                { Label.Computer, "bf967a86-0de6-11d0-a285-00aa003049e2" },
                { Label.Group, "bf967a9c-0de6-11d0-a285-00aa003049e2" },
                { Label.Domain, "19195a5a-6da0-11d0-afd3-00c04fd930c9" },
                { Label.GPO, "f30e3bc2-9ff0-11d1-b603-0000f80367c1" },
                { Label.OU, "bf967aa5-0de6-11d0-a285-00aa003049e2" },
                { Label.Container, "bf967a8b-0de6-11d0-a285-00aa003049e2" },
                { Label.Configuration, "bf967a87-0de6-11d0-a285-00aa003049e2" },
                { Label.RootCA, "3fdfee50-47f4-11d1-a9c3-0000f80367c1" },
                { Label.AIACA, "3fdfee50-47f4-11d1-a9c3-0000f80367c1" },
                { Label.EnterpriseCA, "ee4aa692-3bba-11d2-90cc-00c04fd91ab1" },
                { Label.NTAuthStore, "3fdfee50-47f4-11d1-a9c3-0000f80367c1" },
                { Label.CertTemplate, "e5209ca2-3bba-11d2-90cc-00c04fd91ab1" },
                { Label.IssuancePolicy, "37cfd85c-6719-4ad8-8f9e-8678ba627563" }
            };
        }

        public ACLProcessor(ILdapUtils utils, ILogger log = null)
        {
            _utils = utils;
            _log = log ?? Logging.LogProvider.CreateLogger("ACLProc");
        }

        /// Represents a lightweight Access Control Entry (ACE) used to compute hash values
        /// for AdminSDHolder purposes
        internal class ACEForHashing {
            public string IdentityReference { get; set; }
            public ActiveDirectoryRights Rights { get; set; }
            public AccessControlType AccessControlType { get; set; }
            public string ObjectType { get; set; }
            public string InheritedObjectType { get; set; }
            public InheritanceFlags InheritanceFlags { get; set; }
            /// <summary>
            /// Converts the object to its string representation, providing a meaningful representation for debugging or display purposes.
            /// </summary>
            /// <returns>
            /// A string that represents the current object.
            /// </returns>
            public override string ToString() {
                return $"{IdentityReference}|{Rights}|{AccessControlType}|{ObjectType}|{InheritedObjectType}|{InheritanceFlags}";
            }
        }

        /// <summary>
        ///     Builds a mapping of GUID -> Name for LDAP rights. Used for rights that are created using an extended schema such as
        ///     LAPS
        /// </summary>
        private async Task BuildGuidCache(string domain) {
            lock (_lock) {
                if (_builtDomainCaches.Contains(domain)) {
                    return;
                }

                _builtDomainCaches.Add(domain);
            }

            _log.LogInformation("Building GUID Cache for {Domain}", domain);
            await foreach (var result in _utils.PagedQuery(new LdapQueryParameters {
                DomainName = domain,
                LDAPFilter = "(schemaIDGUID=*)",
                NamingContext = NamingContext.Schema,
                Attributes = new[] { LDAPProperties.SchemaIDGUID, LDAPProperties.Name },
            })) {
                if (result.IsSuccess) {
                    if (!result.Value.TryGetProperty(LDAPProperties.Name, out var name) ||
                        !result.Value.TryGetByteProperty(LDAPProperties.SchemaIDGUID, out var schemaGuid)) {
                        continue;
                    }

                    name = name.ToLower();

                    string guid;
                    try
                    {
                        guid = new Guid(schemaGuid).ToString();
                    }
                    catch
                    {
                        continue;
                    }

                    if (name is LDAPProperties.LAPSPlaintextPassword or LDAPProperties.LAPSEncryptedPassword or LDAPProperties.LegacyLAPSPassword) {
                        _log.LogInformation("Found GUID for ACL Right {Name}: {Guid} in domain {Domain}", name, guid, domain);
                        _guidMap.TryAdd(guid, name);
                    }
                } else {
                    _log.LogDebug("Error while building GUID cache for {Domain}: {Message}", domain, result.Error);
                }
            }

        }

        /// <summary>
        ///     Helper function to use commonlib types in IsACLProtected
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public bool IsACLProtected(IDirectoryObject entry) {
            if (entry.TryGetByteProperty(LDAPProperties.SecurityDescriptor, out var ntSecurityDescriptor)) {
                return IsACLProtected(ntSecurityDescriptor);
            }

            return false;
        }

        /// <summary>
        ///     Gets the protection state of the access control list
        /// </summary>
        /// <param name="ntSecurityDescriptor"></param>
        /// <returns></returns>
        public bool IsACLProtected(byte[] ntSecurityDescriptor) {
            if (ntSecurityDescriptor == null)
                return false;

            var descriptor = _utils.MakeSecurityDescriptor();
            descriptor.SetSecurityDescriptorBinaryForm(ntSecurityDescriptor);

            return descriptor.AreAccessRulesProtected();
        }

        /// <summary>
        ///     Helper function to use commonlib types in IsAdminSDHolderProtected
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public bool? IsAdminSDHolderProtected(IDirectoryObject entry, string adminSdHolderHash = null) {
            if (entry.TryGetByteProperty(LDAPProperties.SecurityDescriptor, out var ntSecurityDescriptor)) {
                entry.TryGetDistinguishedName(out var objectName);
                return IsAdminSDHolderProtected(ntSecurityDescriptor, adminSdHolderHash, objectName);
            }

            return null;
        }

        /// <summary>
        ///     Determines if the security descriptor is protected by AdminSDHolder by comparing its hash
        ///     with the AdminSDHolder hash.
        /// </summary>
        /// <param name="ntSecurityDescriptor">The security descriptor to check</param>
        /// <param name="adminSdHolderHash">The AdminSDHolder hash to compare against</param>
        /// <param name="objectName">The name of the object being checked (for logging)</param>
        /// <returns>
        ///     True if protected by AdminSDHolder, False if not protected, or null if the check couldn't be performed
        /// </returns>
        public bool? IsAdminSDHolderProtected(byte[] ntSecurityDescriptor, string adminSdHolderHash = null, string objectName = "") {
            bool? isAdminSdHolderProtected = null;

            if (ntSecurityDescriptor == null || ntSecurityDescriptor.Length == 0 || string.IsNullOrEmpty(adminSdHolderHash)) {
                _log.LogDebug("Required input(s) missing for AdminSDHolder hash comparison for object: {Name}", objectName);
                return isAdminSdHolderProtected;
            }

            // Calculate the implicit ACL hash for the current object
            string currentObjectHash = CalculateImplicitACLHash(ntSecurityDescriptor, objectName);

            // If we got a valid hash, check if it matches this domain's AdminSDHolder hash
            if (!string.IsNullOrEmpty(currentObjectHash)) {
                _log.LogTrace("Comparing ACL hash {Hash} with AdminSDHolder hashes for {Name}",
                    currentObjectHash, objectName);
                isAdminSdHolderProtected = adminSdHolderHash.Equals(currentObjectHash, StringComparison.OrdinalIgnoreCase);

                if (isAdminSdHolderProtected == true) {
                    _log.LogTrace("Object {Name} is protected by AdminSDHolder", objectName);
                }
            }

            return isAdminSdHolderProtected;
        }

        internal static string CalculateInheritanceHash(string identityReference, ActiveDirectoryRights rights,
            string aceType, string inheritedObjectType)
        {
            var hash = identityReference + rights + aceType + inheritedObjectType;
            /*
             * We're using SHA1 because its fast and this data isn't cryptographically important.
             * Additionally, the chances of a collision in our data size is miniscule and irrelevant.
             * We cannot use MD5 as it is not FIPS compliant and environments can enforce this setting
             */
            try
            {
                using (var sha1 = SHA1.Create())
                {
                    var bytes = sha1.ComputeHash(Encoding.UTF8.GetBytes(hash));
                    return BitConverter.ToString(bytes).Replace("-", string.Empty).ToUpper();
                }
            }
            catch
            {
                return "";
            }
        }

        /// <summary>
        /// Helper function to get inherited ACE hashes using CommonLib types
        /// </summary>
        /// <param name="directoryObject"></param>
        /// <param name="resolvedSearchResult"></param>
        /// <returns></returns>
        public IEnumerable<string> GetInheritedAceHashes(IDirectoryObject directoryObject,
            ResolvedSearchResult resolvedSearchResult) {
            if (directoryObject.TryGetByteProperty(LDAPProperties.SecurityDescriptor, out var value)) {
                return GetInheritedAceHashes(value, resolvedSearchResult.DisplayName);
            }

            return Array.Empty<string>();
        }

        /// <summary>
        /// Calculates a hash of all implicit (non-inherited) ACEs in the security descriptor and the ACL protection status
        /// </summary>
        /// <param name="ntSecurityDescriptor">The raw security descriptor bytes</param>
        /// <param name="objectName">Optional name for logging purposes</param>
        /// <returns>A SHA1 hash of the concatenated implicit ACEs + IsACLProtected, or empty string if error</returns>
        public string CalculateImplicitACLHash(byte[] ntSecurityDescriptor, string objectName = "")
        {
            if (ntSecurityDescriptor == null) {
                _log.LogDebug("Security Descriptor is null for {Name}", objectName);
                return string.Empty;
            }

            _log.LogTrace("Calculating hash of implicit ACEs for {Name}", objectName);
            var descriptor = _utils.MakeSecurityDescriptor();

            try
            {
                descriptor.SetSecurityDescriptorBinaryForm(ntSecurityDescriptor);
            }
            catch (OverflowException)
            {
                _log.LogWarning(
                    "Security descriptor on object {Name} exceeds maximum allowable length. Unable to process",
                    objectName);
                return string.Empty;
            }

            // Check if DACL is protected
            bool isDaclProtected = descriptor.AreAccessRulesProtected();
            _log.LogTrace("DACL Protection status for {Name}: {IsProtected}", objectName, isDaclProtected);

            // Get all ACEs, including Deny ACEs, but skip inherited ones
            var aceList = new List<ACEForHashing>();

            foreach (var ace in descriptor.GetAccessRules(true, false, typeof(SecurityIdentifier))) {
                if (ace == null) {
                    continue; // Skip null ACEs
                }

                var ir = ace.IdentityReference();
                if (ir == null) {
                    _log.LogDebug("Skipping ACE with null identity reference for {Name}", objectName);
                    continue;
                }

                // Create a simplified representation of the ACE for consistent ordering and hashing
                // No filtering of principals - include all principals in the hash calculation
                aceList.Add(new ACEForHashing
                {
                    IdentityReference = ir,
                    Rights = ace.ActiveDirectoryRights(),
                    AccessControlType = ace.AccessControlType(),
                    ObjectType = ace.ObjectType().ToString().ToLower(),
                    InheritedObjectType = ace.InheritedObjectType().ToString().ToLower(),
                    InheritanceFlags = ace.InheritanceFlags,
                });
            }
            // TODO: From here through the end of the method I'm not sure this is the most efficient path forward.
            // Using an IComparer to sort and then instead of string comparison consider serializing data to a byte array

            // Sort the ACEs to ensure consistent ordering
            var sortedAces = aceList.OrderBy(a => a.AccessControlType)
                                   .ThenBy(a => a.IdentityReference)
                                   .ThenBy(a => a.Rights)
                                   .ThenBy(a => a.ObjectType)
                                   .ThenBy(a => a.InheritedObjectType)
                                   .ThenBy(a => a.InheritanceFlags)
                                   .ToList();

            if (sortedAces.Count == 0) {
                _log.LogDebug("No implicit ACEs found for {Name}", objectName);
                return string.Empty;
            }

            // Concatenate all ACE strings & DaclProtected status using pure StringBuilder for performance on large DACLs
            // Calculate more accurate capacity based on first ACE or use a conservative estimate
            var estimatedCapacity = sortedAces.Count > 0 ? sortedAces[0].ToString().Length * sortedAces.Count * 1.2 : 1024;
            var stringBuilder = new StringBuilder((int)estimatedCapacity);
            bool first = true;
            foreach (var ace in sortedAces)
            {
                if (!first)
                    stringBuilder.Append(';');
                else
                    first = false;
                stringBuilder.Append(ace.ToString());
            }
            stringBuilder.Append("|DaclProtected:");
            stringBuilder.Append(isDaclProtected);
            var concatenatedAces = stringBuilder.ToString();


            // Calculate SHA1 hash of the concatenated string
            try
            {
                /*
                * We're using SHA1 because its fast and this data isn't cryptographically important.
                * Additionally, the chances of a collision in our data size is miniscule and irrelevant.
                * We cannot use MD5 as it is not FIPS compliant and environments can enforce this setting
                */
                using var sha1 = SHA1.Create();
                var bytes = sha1.ComputeHash(Encoding.UTF8.GetBytes(concatenatedAces));
                return BitConverter.ToString(bytes).Replace("-", string.Empty).ToUpper();
            }
            catch (Exception ex)
            {
                _log.LogWarning("Error calculating SHA1 hash for {Name}: {Error}", objectName, ex.Message);
                return string.Empty;
            }
        }

        /// <summary>
        /// Gets the hashes for all aces that are pushing inheritance down the tree for later comparison
        /// </summary>
        /// <param name="ntSecurityDescriptor"></param>
        /// <param name="objectName"></param>
        /// <returns></returns>
        public IEnumerable<string> GetInheritedAceHashes(byte[] ntSecurityDescriptor, string objectName = "")
        {
            if (ntSecurityDescriptor == null)
            {
                yield break;
            }

            _log.LogDebug("Processing Inherited ACE hashes for {Name}", objectName);
            var descriptor = _utils.MakeSecurityDescriptor();
            try
            {
                descriptor.SetSecurityDescriptorBinaryForm(ntSecurityDescriptor);
            }
            catch (OverflowException)
            {
                _log.LogWarning(
                    "Security descriptor on object {Name} exceeds maximum allowable length. Unable to process",
                    objectName);
                yield break;
            }

            foreach (var ace in descriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                //Skip all null/deny/inherited aces
                if (ace == null || ace.AccessControlType() == AccessControlType.Deny || ace.IsInherited())
                {
                    continue;
                }

                var ir = ace.IdentityReference();
                var principalSid = Helpers.PreProcessSID(ir);

                //Skip aces for filtered principals
                if (principalSid == null)
                {
                    continue;
                }

                var iFlags = ace.InheritanceFlags;
                if (iFlags == InheritanceFlags.None)
                {
                    continue;
                }

                var aceRights = ace.ActiveDirectoryRights();
                //Lowercase this just in case. As far as I know it should always come back that way anyways, but better safe than sorry
                var aceType = ace.ObjectType().ToString().ToLower();
                var inheritanceType = ace.InheritedObjectType();

                var hash = CalculateInheritanceHash(ir, aceRights, aceType, inheritanceType);
                if (!string.IsNullOrEmpty(hash))
                {
                    yield return hash;
                }
            }
        }

        /// <summary>
        ///     Helper functions to use common lib types and pass appropriate vars to ProcessACL
        /// </summary>
        /// <param name="result"></param>
        /// <param name="searchResult"></param>
        /// <returns></returns>
        public IAsyncEnumerable<ACE> ProcessACL(ResolvedSearchResult result, IDirectoryObject searchResult)
        {
            if (!searchResult.TryGetByteProperty(LDAPProperties.SecurityDescriptor, out var descriptor))
            {
                return AsyncEnumerable.Empty<ACE>();
            }
            return ProcessACL(descriptor, result.Domain, result.ObjectType, searchResult.HasLAPS(), result.DisplayName);
        }

        public IAsyncEnumerable<ACE> ProcessACL(ResolvedSearchResult result, IDirectoryObject searchResult, bool checkForOwnerRights)
        {
            if (!searchResult.TryGetByteProperty(LDAPProperties.SecurityDescriptor, out var descriptor))
            {
                return AsyncEnumerable.Empty<ACE>();
            }
            return ProcessACL(descriptor, result.Domain, result.ObjectType, searchResult.HasLAPS(), checkForOwnerRights, result.DisplayName);
        }

        /// <summary>
        ///     Read's a raw ntSecurityDescriptor and processes the ACEs in the ACL, filtering out ACEs that
        ///     BloodHound is not interested in as well as principals we don't care about
        /// </summary>
        /// <param name="ntSecurityDescriptor"></param>
        /// <param name="objectDomain"></param>
        /// <param name="objectName"></param>
        /// <param name="objectType"></param>
        /// <param name="hasLaps"></param>
        /// <returns></returns>
        public IAsyncEnumerable<ACE> ProcessACL(byte[] ntSecurityDescriptor, string objectDomain,
           Label objectType, bool hasLaps, string objectName = "")
        {
            return ProcessACL(ntSecurityDescriptor, objectDomain, objectType, hasLaps, true, objectName);
        }

        public async IAsyncEnumerable<ACE> ProcessACL(byte[] ntSecurityDescriptor, string objectDomain,
            Label objectType, bool hasLaps, bool checkForOwnerRights, string objectName) {
            await BuildGuidCache(objectDomain);

            if (ntSecurityDescriptor == null) {
                _log.LogDebug("Security Descriptor is null for {Name}", objectName);
                yield break;
            }

            var descriptor = _utils.MakeSecurityDescriptor();
            try {
                descriptor.SetSecurityDescriptorBinaryForm(ntSecurityDescriptor);
            }
            catch (OverflowException) {
                _log.LogWarning(
                    "Security descriptor on object {Name} exceeds maximum allowable length. Unable to process",
                    objectName);
                yield break;
            }

            _log.LogDebug("Processing ACL for {ObjectName}", objectName);
            var ownerSid = Helpers.PreProcessSID(descriptor.GetOwner(typeof(SecurityIdentifier)));

            if (ownerSid != null) {
                if (await _utils.ResolveIDAndType(ownerSid, objectDomain) is (true, var resolvedOwner)) {
                    yield return new ACE {
                        PrincipalType = resolvedOwner.ObjectType,
                        PrincipalSID = resolvedOwner.ObjectIdentifier,
                        RightName = EdgeNames.Owns,
                        IsInherited = false,
                        InheritanceHash = ""
                    };
                }
                else {
                    _log.LogTrace("Failed to resolve owner for {Name}", objectName);
                    yield return new ACE {
                        PrincipalType = Label.Base,
                        PrincipalSID = ownerSid,
                        RightName = EdgeNames.Owns,
                        IsInherited = false,
                        InheritanceHash = ""
                    };
                }
            }

            foreach (var ace in descriptor.GetAccessRules(true, true, typeof(SecurityIdentifier))) {
                bool isPermissionForOwnerRightsSid = false;
                bool isInheritedPermissionForOwnerRightsSid = false;

                if (ace == null || ace.AccessControlType() == AccessControlType.Deny || !ace.IsAceInheritedFrom(BaseGuids[objectType])) {
                    continue;
                }

                var ir = ace.IdentityReference();
                var principalSid = Helpers.PreProcessSID(ir);

                //Preprocess returns null if this is an ignored sid
                if (principalSid == null) {
                    continue;
                }

                var (success, resolvedPrincipal) = await _utils.ResolveIDAndType(principalSid, objectDomain);
                if (!success) {
                    _log.LogTrace("Failed to resolve type for principal {Sid} on ACE for {Object}", principalSid, objectName);
                    resolvedPrincipal.ObjectIdentifier = principalSid;
                    resolvedPrincipal.ObjectType = Label.Base;
                }

                //Check if any rights are explicitly defined for the OWNER RIGHTS SID
                if (checkForOwnerRights && resolvedPrincipal.ObjectIdentifier.EndsWith("S-1-3-4")) {
                    isPermissionForOwnerRightsSid = true;
                }

                var aceRights = ace.ActiveDirectoryRights();
                //Lowercase this just in case. As far as I know it should always come back that way anyways, but better safe than sorry
                var aceType = ace.ObjectType().ToString().ToLower();
                var inherited = ace.IsInherited();

                var aceInheritanceHash = "";
                if (inherited) {
                    aceInheritanceHash = CalculateInheritanceHash(ir, aceRights, aceType, ace.InheritedObjectType());

                    //Check if any rights that are explicitly defined for the OWNER RIGHTS SID are inherited
                    if (checkForOwnerRights && resolvedPrincipal.ObjectIdentifier.EndsWith("S-1-3-4")) {
                        isInheritedPermissionForOwnerRightsSid = true;
                    }
                }

                //// This log is exceptionally noisy, disabling
                // _log.LogTrace("Processing ACE with rights {Rights} and guid {GUID} on object {Name}", aceRights,
                //     aceType, objectName);

                //GenericAll, WriteDacl, and WriteOwner apply to every object
                //All three require ObjectType (aceType) is "AllGuid" or not set (see: https://github.com/SpecterOps/BloodHound/issues/613)
                if (aceType is ACEGuids.AllGuid or "") {
                    if (aceRights.HasFlag(ActiveDirectoryRights.GenericAll)) {
                        yield return new ACE {
                            PrincipalType = resolvedPrincipal.ObjectType,
                            PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                            IsInherited = inherited,
                            RightName = EdgeNames.GenericAll,
                            InheritanceHash = aceInheritanceHash,
                            IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                            IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,

                        };
                        //This is a special case. If we don't continue here, every other ACE will match because GenericAll includes all other permissions
                        continue;
                    }
                    if (aceRights.HasFlag(ActiveDirectoryRights.WriteDacl)) {
                        yield return new ACE {
                            PrincipalType = resolvedPrincipal.ObjectType,
                            PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                            IsInherited = inherited,
                            RightName = EdgeNames.WriteDacl,
                            InheritanceHash = aceInheritanceHash,
                            IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                            IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                        };
                    }
                    if (aceRights.HasFlag(ActiveDirectoryRights.WriteOwner)) {
                        yield return new ACE {
                            PrincipalType = resolvedPrincipal.ObjectType,
                            PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                            IsInherited = inherited,
                            RightName = EdgeNames.WriteOwner,
                            InheritanceHash = aceInheritanceHash,
                            IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                            IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                        };
                    }
                }

                //Cool ACE courtesy of @rookuu. Allows a principal to add itself to a group and no one else
                if (aceRights.HasFlag(ActiveDirectoryRights.Self) &&
                    !aceRights.HasFlag(ActiveDirectoryRights.WriteProperty) &&
                    !aceRights.HasFlag(ActiveDirectoryRights.GenericWrite) && objectType == Label.Group &&
                    aceType is ACEGuids.WriteMember or ACEGuids.AllGuid)
                    yield return new ACE {
                        PrincipalType = resolvedPrincipal.ObjectType,
                        PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                        IsInherited = inherited,
                        RightName = EdgeNames.AddSelf,
                        InheritanceHash = aceInheritanceHash,
                        IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                        IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                    };

                //Process object type specific ACEs. Extended rights apply to users, domains, computers, and cert templates
                if (aceRights.HasFlag(ActiveDirectoryRights.ExtendedRight) ||
                    aceRights.HasFlag(ActiveDirectoryRights.GenericAll)) //GenericAll also works (see: https://github.com/SpecterOps/BloodHound/issues/613#issuecomment-2728437374)
                {
                    if (objectType == Label.Domain) {
                        if (aceType == ACEGuids.DSReplicationGetChanges)
                            yield return new ACE {
                                PrincipalType = resolvedPrincipal.ObjectType,
                                PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                IsInherited = inherited,
                                RightName = EdgeNames.GetChanges,
                                InheritanceHash = aceInheritanceHash,
                                IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                                IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                            };
                        else if (aceType == ACEGuids.DSReplicationGetChangesAll)
                            yield return new ACE {
                                PrincipalType = resolvedPrincipal.ObjectType,
                                PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                IsInherited = inherited,
                                RightName = EdgeNames.GetChangesAll,
                                InheritanceHash = aceInheritanceHash,
                                IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                                IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                            };
                        else if (aceType == ACEGuids.DSReplicationGetChangesInFilteredSet)
                            yield return new ACE {
                                PrincipalType = resolvedPrincipal.ObjectType,
                                PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                IsInherited = inherited,
                                RightName = EdgeNames.GetChangesInFilteredSet,
                                InheritanceHash = aceInheritanceHash,
                                IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                                IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                            };
                        else if (aceType is ACEGuids.AllGuid or "")
                            yield return new ACE {
                                PrincipalType = resolvedPrincipal.ObjectType,
                                PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                IsInherited = inherited,
                                RightName = EdgeNames.AllExtendedRights,
                                InheritanceHash = aceInheritanceHash,
                                IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                                IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                            };
                    }
                    else if (objectType == Label.User) {
                        if (aceType == ACEGuids.UserForceChangePassword)
                            yield return new ACE {
                                PrincipalType = resolvedPrincipal.ObjectType,
                                PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                IsInherited = inherited,
                                RightName = EdgeNames.ForceChangePassword,
                                InheritanceHash = aceInheritanceHash,
                                IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                                IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                            };
                        else if (aceType is ACEGuids.AllGuid or "")
                            yield return new ACE {
                                PrincipalType = resolvedPrincipal.ObjectType,
                                PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                IsInherited = inherited,
                                RightName = EdgeNames.AllExtendedRights,
                                InheritanceHash = aceInheritanceHash,
                                IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                                IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                            };
                    }
                    else if (objectType == Label.Computer) {
                        //ReadLAPSPassword is only applicable if the computer actually has LAPS. Check the world readable property ms-mcs-admpwdexpirationtime
                        if (hasLaps) {
                            if (aceType is ACEGuids.AllGuid or "")
                                yield return new ACE {
                                    PrincipalType = resolvedPrincipal.ObjectType,
                                    PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                    IsInherited = inherited,
                                    RightName = EdgeNames.AllExtendedRights,
                                    InheritanceHash = aceInheritanceHash,
                                    IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                                    IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                                };
                            else if (_guidMap.TryGetValue(aceType, out var lapsAttribute)) {
                                // Compare the retrieved attribute name against LDAPProperties values
                                if (lapsAttribute == LDAPProperties.LegacyLAPSPassword ||
                                    lapsAttribute == LDAPProperties.LAPSPlaintextPassword ||
                                    lapsAttribute == LDAPProperties.LAPSEncryptedPassword) {
                                    yield return new ACE {
                                        PrincipalType = resolvedPrincipal.ObjectType,
                                        PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                        IsInherited = inherited,
                                        RightName = EdgeNames.ReadLAPSPassword,
                                        InheritanceHash = aceInheritanceHash,
                                        IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                                        IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                                    };
                                }
                            }
                        }
                    }
                    else if (objectType == Label.CertTemplate) {
                        if (aceType is ACEGuids.AllGuid or "")
                            yield return new ACE {
                                PrincipalType = resolvedPrincipal.ObjectType,
                                PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                IsInherited = inherited,
                                RightName = EdgeNames.AllExtendedRights,
                                InheritanceHash = aceInheritanceHash,
                                IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                                IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                            };
                        else if (aceType is ACEGuids.Enroll)
                            yield return new ACE {
                                PrincipalType = resolvedPrincipal.ObjectType,
                                PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                IsInherited = inherited,
                                RightName = EdgeNames.Enroll,
                                InheritanceHash = aceInheritanceHash,
                                IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                                IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                            };
                    }
                }

                //GenericWrite encapsulates WriteProperty, so process them in tandem to avoid duplicate edges
                if (aceRights.HasFlag(ActiveDirectoryRights.GenericWrite) ||
                    aceRights.HasFlag(ActiveDirectoryRights.WriteProperty) ||
                    aceRights.HasFlag(ActiveDirectoryRights.GenericAll)) //GenericAll also works (see: https://github.com/SpecterOps/BloodHound/issues/613#issuecomment-2728437374)
                {
                    if (objectType is Label.User
                        or Label.Group
                        or Label.Computer
                        or Label.GPO
                        or Label.OU
                        or Label.Domain
                        or Label.CertTemplate
                        or Label.RootCA
                        or Label.EnterpriseCA
                        or Label.AIACA
                        or Label.NTAuthStore
                        or Label.IssuancePolicy)
                        if (aceType is ACEGuids.AllGuid or "")
                            yield return new ACE {
                                PrincipalType = resolvedPrincipal.ObjectType,
                                PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                IsInherited = inherited,
                                RightName = EdgeNames.GenericWrite,
                                InheritanceHash = aceInheritanceHash,
                                IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                                IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                            };

                    if (objectType == Label.User && aceType == ACEGuids.WriteSPN)
                        yield return new ACE {
                            PrincipalType = resolvedPrincipal.ObjectType,
                            PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                            IsInherited = inherited,
                            RightName = EdgeNames.WriteSPN,
                            InheritanceHash = aceInheritanceHash,
                            IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                            IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                        };
                    else if (objectType == Label.Computer && aceType == ACEGuids.WriteAllowedToAct)
                        yield return new ACE {
                            PrincipalType = resolvedPrincipal.ObjectType,
                            PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                            IsInherited = inherited,
                            RightName = EdgeNames.AddAllowedToAct,
                            InheritanceHash = aceInheritanceHash,
                            IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                            IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                        };
                    else if (objectType == Label.Computer && aceType == ACEGuids.UserAccountRestrictions)
                        yield return new ACE {
                            PrincipalType = resolvedPrincipal.ObjectType,
                            PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                            IsInherited = inherited,
                            RightName = EdgeNames.WriteAccountRestrictions,
                            InheritanceHash = aceInheritanceHash,
                            IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                            IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                        };
                    else if (objectType is Label.OU or Label.Domain && aceType == ACEGuids.WriteGPLink)
                        yield return new ACE {
                            PrincipalType = resolvedPrincipal.ObjectType,
                            PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                            IsInherited = inherited,
                            RightName = EdgeNames.WriteGPLink,
                            InheritanceHash = aceInheritanceHash,
                            IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                            IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                        };
                    else if (objectType == Label.Group && aceType == ACEGuids.WriteMember)
                        yield return new ACE {
                            PrincipalType = resolvedPrincipal.ObjectType,
                            PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                            IsInherited = inherited,
                            RightName = EdgeNames.AddMember,
                            InheritanceHash = aceInheritanceHash,
                            IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                            IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                        };
                    else if (objectType is Label.User or Label.Computer && aceType == ACEGuids.AddKeyPrincipal)
                        yield return new ACE {
                            PrincipalType = resolvedPrincipal.ObjectType,
                            PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                            IsInherited = inherited,
                            RightName = EdgeNames.AddKeyCredentialLink,
                            InheritanceHash = aceInheritanceHash,
                            IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                            IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                        };
                    else if (objectType is Label.CertTemplate) {
                        if (aceType == ACEGuids.PKIEnrollmentFlag)
                            yield return new ACE {
                                PrincipalType = resolvedPrincipal.ObjectType,
                                PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                IsInherited = inherited,
                                RightName = EdgeNames.WritePKIEnrollmentFlag,
                                InheritanceHash = aceInheritanceHash,
                                IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                                IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                            };
                        else if (aceType == ACEGuids.PKINameFlag)
                            yield return new ACE {
                                PrincipalType = resolvedPrincipal.ObjectType,
                                PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                IsInherited = inherited,
                                RightName = EdgeNames.WritePKINameFlag,
                                InheritanceHash = aceInheritanceHash,
                                IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                                IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                            };
                    }
                }

                // EnterpriseCA rights
                if (objectType == Label.EnterpriseCA) {
                    if (aceType is ACEGuids.Enroll)
                        yield return new ACE {
                            PrincipalType = resolvedPrincipal.ObjectType,
                            PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                            IsInherited = inherited,
                            RightName = EdgeNames.Enroll,
                            InheritanceHash = aceInheritanceHash,
                            IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                            IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                        };

                    var cARights = (CertificationAuthorityRights)aceRights;

                    // TODO: These if statements are also present in ProcessRegistryEnrollmentPermissions. Move to shared location.
                    if ((cARights & CertificationAuthorityRights.ManageCA) != 0)
                        yield return new ACE {
                            PrincipalType = resolvedPrincipal.ObjectType,
                            PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                            IsInherited = inherited,
                            RightName = EdgeNames.ManageCA,
                            InheritanceHash = aceInheritanceHash,
                            IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                            IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                        };
                    if ((cARights & CertificationAuthorityRights.ManageCertificates) != 0)
                        yield return new ACE {
                            PrincipalType = resolvedPrincipal.ObjectType,
                            PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                            IsInherited = inherited,
                            RightName = EdgeNames.ManageCertificates,
                            InheritanceHash = aceInheritanceHash,
                            IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                            IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                        };

                    if ((cARights & CertificationAuthorityRights.Enroll) != 0)
                        yield return new ACE {
                            PrincipalType = resolvedPrincipal.ObjectType,
                            PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                            IsInherited = inherited,
                            RightName = EdgeNames.Enroll,
                            InheritanceHash = aceInheritanceHash,
                            IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                            IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                        };
                }
            }
        }


        /// <summary>
        ///     Helper function to use commonlib types and pass to ProcessGMSAReaders
        /// </summary>
        /// <param name="resolvedSearchResult"></param>
        /// <param name="searchResultEntry"></param>
        /// <returns></returns>
        public IAsyncEnumerable<ACE> ProcessGMSAReaders(ResolvedSearchResult resolvedSearchResult,
            IDirectoryObject searchResultEntry) {
            if (!searchResultEntry.TryGetByteProperty(LDAPProperties.GroupMSAMembership, out var descriptor)) {
                return AsyncEnumerable.Empty<ACE>();
            }

            var domain = resolvedSearchResult.Domain;
            var name = resolvedSearchResult.DisplayName;

            return ProcessGMSAReaders(descriptor, name, domain);
        }

        /// <summary>
        ///     ProcessGMSAMembership with no account name
        /// </summary>
        /// <param name="groupMSAMembership"></param>
        /// <param name="objectDomain"></param>
        /// <returns></returns>
        public IAsyncEnumerable<ACE> ProcessGMSAReaders(byte[] groupMSAMembership, string objectDomain) {
            return ProcessGMSAReaders(groupMSAMembership, "", objectDomain);
        }

        /// <summary>
        ///     Processes the msds-groupmsamembership property and returns ACEs representing principals that can read the GMSA
        ///     password from an object
        /// </summary>
        /// <param name="groupMSAMembership"></param>
        /// <param name="objectName"></param>
        /// <param name="objectDomain"></param>
        /// <returns></returns>
        public async IAsyncEnumerable<ACE> ProcessGMSAReaders(byte[] groupMSAMembership, string objectName,
            string objectDomain) {
            if (groupMSAMembership == null) {
                _log.LogDebug("GMSA bytes are null for {Name}", objectName);
                yield break;
            }

            var descriptor = _utils.MakeSecurityDescriptor();
            try {
                descriptor.SetSecurityDescriptorBinaryForm(groupMSAMembership);
            } catch (OverflowException) {
                _log.LogWarning("GMSA ACL length on object {Name} exceeds allowable length. Unable to process",
                    objectName);
                yield break;
            }

            _log.LogDebug("Processing GMSA Readers for {ObjectName}", objectName);
            foreach (var ace in descriptor.GetAccessRules(true, true, typeof(SecurityIdentifier))) {
                if (ace == null || ace.AccessControlType() == AccessControlType.Deny) {
                    continue;
                }

                var ir = ace.IdentityReference();
                var principalSid = Helpers.PreProcessSID(ir);

                if (principalSid == null) {
                    continue;
                }

                _log.LogTrace("Processing GMSA ACE with principal {Principal}", principalSid);

                if (await _utils.ResolveIDAndType(principalSid, objectDomain) is (true, var resolvedPrincipal)) {
                    yield return new ACE {
                        RightName = EdgeNames.ReadGMSAPassword,
                        PrincipalType = resolvedPrincipal.ObjectType,
                        PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                        IsInherited = ace.IsInherited()
                    };
                }
            }
        }
    }
}
