using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using SharpHoundCommonLib.Enums;
using Microsoft.Extensions.Logging;
using System.IO;
using System.Security;
using SharpHoundCommonLib.Processors;
using Microsoft.Win32;

namespace SharpHoundCommonLib {
    public static class Helpers {
        private static readonly HashSet<string> Groups = new() { "268435456", "268435457", "536870912", "536870913" };
        private static readonly HashSet<string> Computers = new() { "805306369" };
        private static readonly HashSet<string> Users = new() { "805306368" };

        private static readonly Regex DCReplaceRegex = new("DC=", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        private static readonly Regex SPNRegex = new(@".*\/.*", RegexOptions.Compiled);
        private static readonly DateTime EpochDiff = new(1970, 1, 1);

        private static readonly string[] FilteredSids = {
            "S-1-5-3", "S-1-5-4", "S-1-5-6", "S-1-2", "S-1-2-0", "S-1-5-17", "S-1-5-18",
            "S-1-5-19", "S-1-5-20", "S-1-0-0", "S-1-0", "S-1-2-1"
        };

        public static string RemoveDistinguishedNamePrefix(string distinguishedName) {
            if (!distinguishedName.Contains(",")) {
                return "";
            }

            if (distinguishedName.IndexOf("DC=", StringComparison.OrdinalIgnoreCase) < 0) {
                return "";
            }

            //Start at the first instance of a comma, and continue to loop while we still have commas. If we get -1, it means we ran out of commas.
            //This allows us to cleanly iterate over all indexes of commas in our DNs and find the first non-escaped one
            for (var i = distinguishedName.IndexOf(','); i > -1; i = distinguishedName.IndexOf(',', i + 1)) {
                //If there's a comma at the beginning of the DN, something screwy is going on. Just ignore it
                if (i == 0) {
                    continue;
                }

                //This indicates an escaped comma, which we should not use to split a DN
                if (distinguishedName[i - 1] == '\\') {
                    continue;
                }

                //This is an unescaped comma, so snip our DN from this comma onwards and return this as the cleaned distinguished name
                return distinguishedName.Substring(i + 1);
            }

            return "";
        }

        /// <summary>
        ///     Splits a GPLink property into its representative parts
        ///     Filters disabled links by default
        /// </summary>
        /// <param name="linkProp"></param>
        /// <param name="filterDisabled"></param>
        /// <returns></returns>
        public static IEnumerable<ParsedGPLink> SplitGPLinkProperty(string linkProp, bool filterDisabled = true) {
            foreach (var link in linkProp.Split(']', '[')
                         .Where(x => x.StartsWith("LDAP", StringComparison.OrdinalIgnoreCase))) {
                var s = link.Split(';');
                var dn = s[0].Substring(s[0].IndexOf("CN=", StringComparison.OrdinalIgnoreCase));
                var status = s[1];

                if (filterDisabled)
                    // 1 and 3 represent Disabled, Not Enforced and Disabled, Enforced respectively.
                    if (status is "3" or "1")
                        continue;

                yield return new ParsedGPLink {
                    Status = status.TrimStart().TrimEnd(),
                    DistinguishedName = dn.TrimStart().TrimEnd()
                };
            }
        }

        /// <summary>
        ///     Attempts to convert a SamAccountType value to the appropriate type enum
        /// </summary>
        /// <param name="samAccountType"></param>
        /// <returns><c>Label</c> value representing type</returns>
        public static Label SamAccountTypeToType(string samAccountType) {
            if (Groups.Contains(samAccountType))
                return Label.Group;

            if (Users.Contains(samAccountType))
                return Label.User;

            if (Computers.Contains(samAccountType))
                return Label.Computer;

            return Label.Base;
        }

        /// <summary>
        ///     Converts a string SID to its hex representation for LDAP searches
        /// </summary>
        /// <param name="sid">String security identifier to convert</param>
        /// <returns>String representation to use in LDAP filters</returns>
        public static string ConvertSidToHexSid(string sid) {
            var securityIdentifier = new SecurityIdentifier(sid);
            var sidBytes = new byte[securityIdentifier.BinaryLength];
            securityIdentifier.GetBinaryForm(sidBytes, 0);

            var output = $"\\{BitConverter.ToString(sidBytes).Replace('-', '\\')}";
            return output;
        }

        /// <summary>
        ///     Converts a string GUID to its hex representation for LDAP searches
        /// </summary>
        /// <param name="guid"></param>
        /// <returns></returns>
        public static string ConvertGuidToHexGuid(string guid) {
            var guidObj = new Guid(guid);
            var guidBytes = guidObj.ToByteArray();
            var output = $"\\{BitConverter.ToString(guidBytes).Replace('-', '\\')}";
            return output;
        }

        /// <summary>
        ///     Extracts an active directory domain name from a DistinguishedName
        /// </summary>
        /// <param name="distinguishedName">Distinguished Name to extract domain from</param>
        /// <returns>String representing the domain name of this object</returns>
        public static string DistinguishedNameToDomain(string distinguishedName) {
            int idx;
            if (distinguishedName.ToUpper().Contains("DELETED OBJECTS")) {
                idx = distinguishedName.IndexOf("DC=", 3, StringComparison.Ordinal);
            } else {
                idx = distinguishedName.IndexOf("DC=",
                    StringComparison.CurrentCultureIgnoreCase);
            }

            if (idx < 0)
                return null;

            var temp = distinguishedName.Substring(idx);
            temp = DCReplaceRegex.Replace(temp, "").Replace(",", ".").ToUpper();
            return temp;
        }

        /// <summary>
        /// Converts a domain name to a distinguished name using simple string substitution
        /// </summary>
        /// <param name="domainName"></param>
        /// <returns></returns>
        public static string DomainNameToDistinguishedName(string domainName) {
            return $"DC={domainName.Replace(".", ",DC=")}";
        }

        /// <summary>
        ///     Strips a "serviceprincipalname" entry down to just its hostname
        /// </summary>
        /// <param name="target">Raw service principal name</param>
        /// <returns>Stripped service principal name with (hopefully) just the hostname</returns>
        public static string StripServicePrincipalName(string target) {
            return SPNRegex.IsMatch(target) ? target.Split('/')[1].Split(':')[0] : target;
        }

        /// <summary>
        ///     Converts a string to its base64 representation
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static string Base64(string input) {
            var plainBytes = Encoding.UTF8.GetBytes(input);
            return Convert.ToBase64String(plainBytes);
        }

        /// <summary>
        ///     Converts a windows file time to unix epoch time
        /// </summary>
        /// <param name="ldapTime"></param>
        /// <returns></returns>
        public static long ConvertFileTimeToUnixEpoch(string ldapTime) {
            if (ldapTime == null)
                return -1;

            var time = long.Parse(ldapTime);
            if (time == 0)
                return 0;

            long toReturn;

            try {
                toReturn = (long)Math.Floor(DateTime.FromFileTimeUtc(time).Subtract(EpochDiff).TotalSeconds);
            } catch {
                toReturn = -1;
            }

            return toReturn;
        }

        /// <summary>
        ///     Converts a windows file time to unix epoch time
        /// </summary>
        /// <param name="ldapTime"></param>
        /// <returns></returns>
        public static long ConvertTimestampToUnixEpoch(string ldapTime) {
            try {
                var dt = DateTime.ParseExact(ldapTime, "yyyyMMddHHmmss.0K", CultureInfo.CurrentCulture).ToUniversalTime();
                return (long)dt.Subtract(EpochDiff).TotalSeconds;
            } catch {
                return 0;
            }
        }

        /// <summary>
        ///     Converts an LDAP time string into a long
        /// </summary>
        /// <param name="ldapTime"></param>
        /// <returns></returns>
        public static long ConvertLdapTimeToLong(string ldapTime) {
            if (ldapTime == null)
                return -1;

            var time = long.Parse(ldapTime);
            return time;
        }

        /// <summary>
        ///     Removes some commonly seen SIDs that have no use in the schema
        /// </summary>
        /// <param name="sid"></param>
        /// <returns></returns>
        internal static string PreProcessSID(string sid) {
            sid = sid?.ToUpper();
            if (sid != null)
                //Ignore Local System/Creator Owner/Principal Self
                return sid is "S-1-5-18" or "S-1-3-0" or "S-1-5-10" ? null : sid;

            return null;
        }

        public static bool IsSidFiltered(string sid) {
            //Uppercase just in case we get a lowercase s
            sid = sid.ToUpper();
            if (sid.StartsWith("S-1-5-80") || sid.StartsWith("S-1-5-82") ||
                sid.StartsWith("S-1-5-90") || sid.StartsWith("S-1-5-96"))
                return true;

            if (FilteredSids.Contains(sid))
                return true;

            return false;
        }

        public static RegistryResult GetRegistryKeyData(string target, string subkey, string subvalue, ILogger log) {
            var data = new RegistryResult();

            try {
                var baseKey = OpenRemoteRegistry(target);
                var value = baseKey.GetValue(subkey, subvalue);
                data.Value = value;

                data.Collected = true;
            } catch (IOException e) {
                log.LogDebug(e, "Error getting data from registry for {Target}: {RegSubKey}:{RegValue}",
                    target, subkey, subvalue);
                data.FailureReason = "Target machine was not found or not connectable";
            } catch (SecurityException e) {
                log.LogDebug(e, "Error getting data from registry for {Target}: {RegSubKey}:{RegValue}",
                    target, subkey, subvalue);
                data.FailureReason = "User does not have the proper permissions to perform this operation";
            } catch (UnauthorizedAccessException e) {
                log.LogDebug(e, "Error getting data from registry for {Target}: {RegSubKey}:{RegValue}",
                    target, subkey, subvalue);
                data.FailureReason = "User does not have the necessary registry rights";
            } catch (Exception e) {
                log.LogDebug(e, "Error getting data from registry for {Target}: {RegSubKey}:{RegValue}",
                    target, subkey, subvalue);
                data.FailureReason = e.Message;
            }

            return data;
        }

        public static IRegistryKey OpenRemoteRegistry(string target) {
            var key = new SHRegistryKey(RegistryHive.LocalMachine, target);
            return key;
        }

        public static string[] AuthenticationOIDs = new string[] {
            CommonOids.ClientAuthentication,
            CommonOids.PKINITClientAuthentication,
            CommonOids.SmartcardLogon,
            CommonOids.AnyPurpose
        };

        public static string[] SchannelAuthenticationOIDs = new string[] {
            CommonOids.ClientAuthentication,
            CommonOids.AnyPurpose
        };
        
        public static string DumpDirectoryObject(this IDirectoryObject directoryObject) {
            var builder = new StringBuilder();
            builder.AppendLine("PropertyName : PropertyValue");
            foreach (var prop in directoryObject.PropertyNames()) {
                builder.AppendLine($"{prop} : {directoryObject.GetProperty(prop)}");
            }

            return builder.ToString();
        }
    }

    public class ParsedGPLink {
        public string DistinguishedName { get; set; }
        public string Status { get; set; }
    }
}