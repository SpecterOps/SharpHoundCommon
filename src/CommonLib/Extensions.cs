using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.LDAPQueries;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;

namespace SharpHoundCommonLib
{
    public static class Extensions
    {
        private const string GMSAClass = "msds-groupmanagedserviceaccount";
        private const string MSAClass = "msds-managedserviceaccount";
        private static readonly ILogger Log;

        static Extensions()
        {
            Log = Logging.LogProvider.CreateLogger("Extensions");
        }

        internal static async Task<List<T>> ToListAsync<T>(this IAsyncEnumerable<T> items)
        {
            var results = new List<T>();
            await foreach (var item in items
                               .ConfigureAwait(false))
                results.Add(item);
            return results;
        }

        /// <summary>
        ///     Helper function to print attributes of a SearchResultEntry
        /// </summary>
        /// <param name="searchResultEntry"></param>
        public static string PrintEntry(this SearchResultEntry searchResultEntry)
        {
            var sb = new StringBuilder();
            if (searchResultEntry.Attributes.AttributeNames == null) return sb.ToString();
            foreach (var propertyName in searchResultEntry.Attributes.AttributeNames)
            {
                var property = propertyName.ToString();
                sb.Append(property).Append("\t").Append(searchResultEntry.GetProperty(property)).Append("\n");
            }

            return sb.ToString();
        }

        public static string LdapValue(this SecurityIdentifier s)
        {
            var bytes = new byte[s.BinaryLength];
            s.GetBinaryForm(bytes, 0);

            var output = $"\\{BitConverter.ToString(bytes).Replace('-', '\\')}";
            return output;
        }

        public static string LdapValue(this Guid s)
        {
            var bytes = s.ToByteArray();
            var output = $"\\{BitConverter.ToString(bytes).Replace('-', '\\')}";
            return output;
        }

        public static string GetSid(this DirectoryEntry result)
        {
            try
            {
                if (!result.Properties.Contains(LDAPProperties.ObjectSID))
                    return null;
            }
            catch
            {
                return null;
            }

            var s = result.Properties[LDAPProperties.ObjectSID][0];
            return s switch
            {
                byte[] b => new SecurityIdentifier(b, 0).ToString(),
                string st => new SecurityIdentifier(Encoding.ASCII.GetBytes(st), 0).ToString(),
                _ => null
            };
        }

        /// <summary>
        ///     Returns true if any computer collection methods are set
        /// </summary>
        /// <param name="methods"></param>
        /// <returns></returns>
        public static bool IsComputerCollectionSet(this ResolvedCollectionMethod methods)
        {
            return (methods & ResolvedCollectionMethod.ComputerOnly) != 0;
        }

        /// <summary>
        ///     Returns true if any local group collections are set
        /// </summary>
        /// <param name="methods"></param>
        /// <returns></returns>
        public static bool IsLocalGroupCollectionSet(this ResolvedCollectionMethod methods)
        {
            return (methods & ResolvedCollectionMethod.LocalGroups) != 0;
        }

        /// <summary>
        ///     Gets the relative identifier for a SID
        /// </summary>
        /// <param name="securityIdentifier"></param>
        /// <returns></returns>
        public static int Rid(this SecurityIdentifier securityIdentifier)
        {
            var value = securityIdentifier.Value;
            var rid = int.Parse(value.Substring(value.LastIndexOf("-", StringComparison.Ordinal) + 1));
            return rid;
        }

        #region SearchResultEntry

        /// <summary>
        ///     Gets the specified property as a string from the SearchResultEntry
        /// </summary>
        /// <param name="entry"></param>
        /// <param name="property">The LDAP name of the property you want to get</param>
        /// <returns>The string value of the property if it exists or null</returns>
        public static string GetProperty(this SearchResultEntry entry, string property)
        {
            if (!entry.Attributes.Contains(property))
                return null;

            var collection = entry.Attributes[property];
            //Use GetValues to auto-convert to the proper type
            var lookups = collection.GetValues(typeof(string));
            if (lookups.Length == 0)
                return null;

            if (lookups[0] is not string prop || prop.Length == 0)
                return null;

            return prop;
        }

        /// <summary>
        ///     Get's the string representation of the "objectguid" property from the SearchResultEntry
        /// </summary>
        /// <param name="entry"></param>
        /// <returns>The string representation of the object's GUID if possible, otherwise null</returns>
        public static string GetGuid(this SearchResultEntry entry)
        {
            if (entry.Attributes.Contains(LDAPProperties.ObjectGUID))
            {
                var guidBytes = entry.GetPropertyAsBytes(LDAPProperties.ObjectGUID);

                return new Guid(guidBytes).ToString().ToUpper();
            }

            return null;
        }

        /// <summary>
        ///     Gets the "objectsid" property as a string from the SearchResultEntry
        /// </summary>
        /// <param name="entry"></param>
        /// <returns>The string representation of the object's SID if possible, otherwise null</returns>
        public static string GetSid(this SearchResultEntry entry)
        {
            if (!entry.Attributes.Contains(LDAPProperties.ObjectSID)) return null;

            object[] s;
            try
            {
                s = entry.Attributes[LDAPProperties.ObjectSID].GetValues(typeof(byte[]));
            }
            catch (NotSupportedException)
            {
                return null;
            }

            if (s.Length == 0)
                return null;

            if (s[0] is not byte[] sidBytes || sidBytes.Length == 0)
                return null;

            try
            {
                var sid = new SecurityIdentifier(sidBytes, 0);
                return sid.Value.ToUpper();
            }
            catch (ArgumentNullException)
            {
                return null;
            }
        }

        /// <summary>
        ///     Gets the specified property as a string array from the SearchResultEntry
        /// </summary>
        /// <param name="entry"></param>
        /// <param name="property">The LDAP name of the property you want to get</param>
        /// <returns>The specified property as an array of strings if possible, else an empty array</returns>
        public static string[] GetPropertyAsArray(this SearchResultEntry entry, string property)
        {
            if (!entry.Attributes.Contains(property))
                return Array.Empty<string>();

            var values = entry.Attributes[property];
            var strings = values.GetValues(typeof(string));

            return strings is not string[] result ? Array.Empty<string>() : result;
        }

        /// <summary>
        ///     Gets the specified property as an array of byte arrays from the SearchResultEntry
        ///     Used for SIDHistory
        /// </summary>
        /// <param name="entry"></param>
        /// <param name="property">The LDAP name of the property you want to get</param>
        /// <returns>The specified property as an array of bytes if possible, else an empty array</returns>
        public static byte[][] GetPropertyAsArrayOfBytes(this SearchResultEntry entry, string property)
        {
            if (!entry.Attributes.Contains(property))
                return Array.Empty<byte[]>();

            var values = entry.Attributes[property];
            var bytes = values.GetValues(typeof(byte[]));

            return bytes is not byte[][] result ? Array.Empty<byte[]>() : result;
        }

        /// <summary>
        ///     Gets the specified property as a byte array
        /// </summary>
        /// <param name="searchResultEntry"></param>
        /// <param name="property">The LDAP name of the property you want to get</param>
        /// <returns>An array of bytes if possible, else null</returns>
        public static byte[] GetPropertyAsBytes(this SearchResultEntry searchResultEntry, string property)
        {
            if (!searchResultEntry.Attributes.Contains(property))
                return null;

            var collection = searchResultEntry.Attributes[property];
            var lookups = collection.GetValues(typeof(byte[]));

            if (lookups.Length == 0)
                return Array.Empty<byte>();

            if (lookups[0] is not byte[] bytes || bytes.Length == 0)
                return Array.Empty<byte>();

            return bytes;
        }

        /// <summary>
        ///     Gets the specified property as an int
        /// </summary>
        /// <param name="entry"></param>
        /// <param name="property"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public static bool GetPropertyAsInt(this SearchResultEntry entry, string property, out int value)
        {
            var prop = entry.GetProperty(property);
            if (prop != null) return int.TryParse(prop, out value);
            value = 0;
            return false;
        }

        /// <summary>
        ///     Gets the specified property as an array of X509 certificates.
        /// </summary>
        /// <param name="searchResultEntry"></param>
        /// <param name="property"></param>
        /// <returns></returns>
        public static X509Certificate2[] GetPropertyAsArrayOfCertificates(this SearchResultEntry searchResultEntry,
            string property)
        {
            if (!searchResultEntry.Attributes.Contains(property))
                return null;

            return searchResultEntry.GetPropertyAsArrayOfBytes(property).Select(x => new X509Certificate2(x)).ToArray();
        }


        /// <summary>
        ///     Attempts to get the unique object identifier as used by BloodHound for the Search Result Entry. Tries to get
        ///     objectsid first, and then objectguid next.
        /// </summary>
        /// <param name="entry"></param>
        /// <returns>String representation of the entry's object identifier or null</returns>
        public static string GetObjectIdentifier(this SearchResultEntry entry)
        {
            return entry.GetSid() ?? entry.GetGuid();
        }

        /// <summary>
        ///     Checks the isDeleted LDAP property to determine if an entry has been deleted from the directory
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public static bool IsDeleted(this SearchResultEntry entry)
        {
            var deleted = entry.GetProperty(LDAPProperties.IsDeleted);
            return bool.TryParse(deleted, out var isDeleted) && isDeleted;
        }

        /// <summary>
        ///     Extension method to determine the BloodHound type of a SearchResultEntry using LDAP properties
        ///     Requires ldap properties objectsid, samaccounttype, objectclass
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public static Label GetLabel(this SearchResultEntry entry)
        {
            var objectId = entry.GetObjectIdentifier();

            if (objectId == null)
            {
                Log.LogWarning("Failed to get an object identifier for {DN}", entry.DistinguishedName);
                return Label.Base;
            }

            if (objectId.StartsWith("S-1") &&
                WellKnownPrincipal.GetWellKnownPrincipal(objectId, out var commonPrincipal))
            {
                Log.LogDebug("GetLabel - {ObjectID} is a WellKnownPrincipal with {Type}", objectId,
                    commonPrincipal.ObjectType);
                return commonPrincipal.ObjectType;
            }


            var objectType = Label.Base;
            var samAccountType = entry.GetProperty(LDAPProperties.SAMAccountType);
            var objectClasses = entry.GetPropertyAsArray(LDAPProperties.ObjectClass);

            //Override object class for GMSA/MSA accounts
            if (objectClasses != null && (objectClasses.Contains(MSAClass, StringComparer.OrdinalIgnoreCase) ||
                                          objectClasses.Contains(GMSAClass, StringComparer.OrdinalIgnoreCase)))
            {
                Log.LogDebug("GetLabel - {ObjectID} is an MSA/GMSA, returning User", objectId);
                Cache.AddConvertedValue(entry.DistinguishedName, objectId);
                Cache.AddType(objectId, objectType);
                return Label.User;
            }


            //Its not a common principal. Lets use properties to figure out what it actually is
            if (samAccountType != null) objectType = Helpers.SamAccountTypeToType(samAccountType);

            Log.LogDebug("GetLabel - SamAccountTypeToType returned {Label}", objectType);
            if (objectType != Label.Base)
            {
                Cache.AddConvertedValue(entry.DistinguishedName, objectId);
                Cache.AddType(objectId, objectType);
                return objectType;
            }


            if (objectClasses == null)
            {
                Log.LogDebug("GetLabel - ObjectClasses for {ObjectID} is null", objectId);
                objectType = Label.Base;
            }
            else
            {
                Log.LogDebug("GetLabel - ObjectClasses for {ObjectID}: {Classes}", objectId,
                    string.Join(", ", objectClasses));
                if (objectClasses.Contains(GroupPolicyContainerClass, StringComparer.InvariantCultureIgnoreCase))
                    objectType = Label.GPO;
                else if (objectClasses.Contains(OrganizationalUnitClass, StringComparer.InvariantCultureIgnoreCase))
                    objectType = Label.OU;
                else if (objectClasses.Contains(DomainClass, StringComparer.InvariantCultureIgnoreCase))
                    objectType = Label.Domain;
                else if (objectClasses.Contains(ContainerClass, StringComparer.InvariantCultureIgnoreCase))
                    objectType = Label.Container;
                else if (objectClasses.Contains(ConfigurationClass, StringComparer.InvariantCultureIgnoreCase))
                    objectType = Label.Configuration;
                else if (objectClasses.Contains(PKICertificateTemplateClass, StringComparer.InvariantCultureIgnoreCase))
                    objectType = Label.CertTemplate;
                else if (objectClasses.Contains(PKIEnrollmentServiceClass, StringComparer.InvariantCultureIgnoreCase))
                    objectType = Label.EnterpriseCA;
                else if (objectClasses.Contains(CertificationAuthorityClass, StringComparer.InvariantCultureIgnoreCase))
                {
                    if (entry.DistinguishedName.Contains(DirectoryPaths.RootCALocation))
                        objectType = Label.RootCA;
                    else if (entry.DistinguishedName.Contains(DirectoryPaths.AIACALocation))
                        objectType = Label.AIACA;
                    else if (entry.DistinguishedName.Contains(DirectoryPaths.NTAuthStoreLocation))
                        objectType = Label.NTAuthStore;
                }else if (objectClasses.Contains(OIDContainerClass, StringComparer.InvariantCultureIgnoreCase))
                {
                    if (entry.DistinguishedName.StartsWith(DirectoryPaths.OIDContainerLocation,
                            StringComparison.InvariantCultureIgnoreCase))
                        objectType = Label.Container;
                    else
                    {
                        if (entry.GetPropertyAsInt(LDAPProperties.Flags, out var flags) && flags == 2)
                        {
                            objectType = Label.IssuancePolicy;    
                        }
                    }
                }
            }

            Log.LogDebug("GetLabel - Final label for {ObjectID}: {Label}", objectId, objectType);

            Cache.AddConvertedValue(entry.DistinguishedName, objectId);
            Cache.AddType(objectId, objectType);
            return objectType;
        }

        private const string GroupPolicyContainerClass = "groupPolicyContainer";
        private const string OrganizationalUnitClass = "organizationalUnit";
        private const string DomainClass = "domain";
        private const string ContainerClass = "container";
        private const string ConfigurationClass = "configuration";
        private const string PKICertificateTemplateClass = "pKICertificateTemplate";
        private const string PKIEnrollmentServiceClass = "pKIEnrollmentService";
        private const string CertificationAuthorityClass = "certificationAuthority";
        private const string OIDContainerClass = "msPKI-Enterprise-Oid";

        #endregion
    }
}