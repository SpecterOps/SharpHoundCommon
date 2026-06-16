using System;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Runtime.Serialization;
using SharpHoundCommonLib.Enums;

namespace SharpHoundCommonLib
{
    [DataContract]
    public class Cache
    {
        //Leave these here until we switch back to Newtonsoft which doesn't suck
        // [DataMember]private ConcurrentDictionary<string, string[]> _globalCatalogCache;
        //
        // [DataMember]private ConcurrentDictionary<string, Label> _idToTypeCache;
        //
        // [DataMember]private ConcurrentDictionary<string, string> _machineSidCache;
        //
        // [DataMember]private ConcurrentDictionary<string, string> _sidToDomainCache;
        //
        // [DataMember]private ConcurrentDictionary<string, string> _valueToIDCache;

        private static Version defaultVersion = new(1, 0, 0);
        
        private Cache()
        {
            ValueToIdCache = new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            IdToTypeCache = new ConcurrentDictionary<string, Label>();
            GlobalCatalogCache = new ConcurrentDictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
            MachineSidCache = new ConcurrentDictionary<string, string>();
            SIDToDomainCache = new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }

        [DataMember] public ConcurrentDictionary<string, string[]> GlobalCatalogCache { get; private set; }

        [DataMember] public ConcurrentDictionary<string, Label> IdToTypeCache { get; private set; }

        [DataMember] public ConcurrentDictionary<string, string> MachineSidCache { get; private set; }

        [DataMember] public ConcurrentDictionary<string, string> SIDToDomainCache { get; private set; }

        [DataMember] public ConcurrentDictionary<string, string> ValueToIdCache { get; private set; }
        [DataMember] public DateTime CacheCreationDate { get; set; }
        [DataMember] public Version CacheCreationVersion { get; set; }

        [IgnoreDataMember] private static Cache CacheInstance { get; set; }

        /// <summary>
        ///     Add a SID/Domain-name pair to the cache. The Name→SID direction is always written
        ///     (NetBIOS aliases are valid lookup keys). The SID→Name direction is only written
        ///     when the name is a DNS-shaped FQDN: a NetBIOS-keyed reverse write would poison
        ///     the slot for downstream consumers that depend on the SID→Name lookup yielding a
        ///     DNS name (LDAP base DN construction, server selection, GetDomainInfoAsync hints).
        ///     Existing entries are preserved (TryAdd semantics) — first resolver wins.
        /// </summary>
        /// <param name="key">A SID or a domain name.</param>
        /// <param name="value">The corresponding domain name or SID.</param>
        internal static void AddDomainSidMapping(string key, string value)
        {
            if (CacheInstance == null) return;
            if (string.IsNullOrEmpty(key) || string.IsNullOrEmpty(value)) return;

            var keyIsSid = LooksLikeDomainSid(key);
            var valueIsSid = LooksLikeDomainSid(value);

            if (keyIsSid == valueIsSid)
            {
                // Both look like SIDs or neither does — caller misuse or an unexpected input
                // shape. Throw this data out
                return;
            }

            var sid = keyIsSid ? key : value;
            var name = keyIsSid ? value : key;

            CacheInstance.SIDToDomainCache.TryAdd(name, sid);

            if (LooksLikeDnsDomainName(name))
            {
                CacheInstance.SIDToDomainCache.TryAdd(sid, name);
            }
        }

        private static bool LooksLikeDomainSid(string value)
        {
            return value != null && value.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase);
        }

        // Gates the SID->Name reverse cache write. Downstream consumers (LDAP base DN
        // construction, server selection, GetDomainInfoAsync hint resolution) treat the value in
        // that slot as an FQDN they can split on '.' and feed to DC=/CN=Partitions queries, so
        // a NetBIOS alias, an IPv4 literal, or a malformed label set in this slot poisons every
        // downstream lookup for the SID. The check enforces RFC-1035-shaped multi-label DNS:
        // total length <= 253, >= 2 non-empty labels, each label 1-63 chars of [A-Za-z0-9-]
        // with no leading/trailing hyphen, and not an IPv4 literal (four all-digit labels).
        // Single-label AD domains (e.g., a forest root literally named "CORP") are deliberately
        // rejected: a single label is syntactically indistinguishable from a NetBIOS alias and
        // we'd rather slow-path-resolve them than silently cache the wrong shape.
        private static bool LooksLikeDnsDomainName(string value)
        {
            if (string.IsNullOrEmpty(value) || value.Length > 253) return false;

            var labels = value.Split('.');
            if (labels.Length < 2) return false;

            var allNumeric = true;
            foreach (var label in labels)
            {
                if (!IsValidDnsLabel(label)) return false;
                if (allNumeric && !IsAllDigits(label)) allNumeric = false;
            }

            // Reject IPv4 literals after per-label validation so we don't preempt a malformed-input
            // rejection with a shape-based one (the diagnostic value is in the per-label check).
            return !(labels.Length == 4 && allNumeric);
        }

        private static bool IsValidDnsLabel(string label)
        {
            if (label.Length == 0 || label.Length > 63) return false;
            if (label[0] == '-' || label[label.Length - 1] == '-') return false;

            foreach (var c in label)
            {
                var isDigit = c >= '0' && c <= '9';
                var isAlpha = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
                if (!isDigit && !isAlpha && c != '-') return false;
            }
            return true;
        }

        private static bool IsAllDigits(string s)
        {
            foreach (var c in s)
            {
                if (c < '0' || c > '9') return false;
            }
            return true;
        }

        /// <summary>
        ///     Get a SID to Domain or Domain to SID mapping
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        internal static bool GetDomainSidMapping(string key, out string value)
        {
            if (CacheInstance != null) return CacheInstance.SIDToDomainCache.TryGetValue(key, out value);
            value = null;
            return false;
        }

        /// <summary>
        ///     Add a Domain SID -> Computer SID mapping to the cache
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        internal static void AddMachineSid(string key, string value)
        {
            CacheInstance?.MachineSidCache.TryAdd(key, value);
        }

        internal static bool GetMachineSid(string key, out string value)
        {
            if (CacheInstance != null) return CacheInstance.MachineSidCache.TryGetValue(key, out value);
            value = null;
            return false;
        }

        internal static void AddPrefixedValue(string key, string domain, string value)
        {
            CacheInstance?.ValueToIdCache.TryAdd(GetPrefixKey(key, domain), value);
        }

        internal static void AddType(string key, Label value)
        {
            CacheInstance?.IdToTypeCache.TryAdd(key, value);
        }

        internal static void AddGCCache(string key, string[] value)
        {
            CacheInstance?.GlobalCatalogCache?.TryAdd(key, value);
        }

        internal static bool GetGCCache(string key, out string[] value)
        {
            if (CacheInstance != null) return CacheInstance.GlobalCatalogCache.TryGetValue(key, out value);
            value = null;
            return false;
        }

        internal static bool GetPrefixedValue(string key, string domain, out string value)
        {
            if (CacheInstance != null)
                return CacheInstance.ValueToIdCache.TryGetValue(GetPrefixKey(key, domain), out value);
            value = null;
            return false;
        }

        internal static bool GetIDType(string key, out Label value)
        {
            if (CacheInstance != null) return CacheInstance.IdToTypeCache.TryGetValue(key, out value);
            value = Label.Base;
            return false;
        }

        private static string GetPrefixKey(string key, string domain)
        {
            return $"{key}|{domain}";
        }

        /// <summary>
        ///     Creates a new empty cache instance
        /// </summary>
        /// <returns></returns>
        public static Cache CreateNewCache(Version version = null)
        {
            if (version == null)
            {
                version = defaultVersion;
            }
            return new Cache
            {
                CacheCreationVersion = version,
                CacheCreationDate = DateTime.Now.Date
            };
        }

        /// <summary>
        ///     Sets the cache instance being used by the common library
        /// </summary>
        /// <param name="cache"></param>
        public static void SetCacheInstance(Cache cache)
        {
            CacheInstance = cache;
            NormalizeCaseInsensitiveCaches();
            CreateMissingDictionaries();
        }

        /// <summary>
        ///     Rewraps dictionaries that must be case-insensitive after assignment. Serializers
        ///     (DataContractSerializer, Newtonsoft.Json, System.Text.Json) reconstruct
        ///     <see cref="ConcurrentDictionary{TKey,TValue}"/> via its parameterless constructor,
        ///     which produces a case-sensitive instance regardless of how the dictionary was
        ///     created prior to serialization. Without this rewrap, a loaded cache silently
        ///     regresses the case-insensitive invariants applied at construction time.
        /// </summary>
        private static void NormalizeCaseInsensitiveCaches()
        {
            if (CacheInstance == null) return;
            if (CacheInstance.SIDToDomainCache != null)
            {
                CacheInstance.SIDToDomainCache = CopyCaseInsensitive(CacheInstance.SIDToDomainCache);
            }
            if (CacheInstance.GlobalCatalogCache != null)
            {
                CacheInstance.GlobalCatalogCache = CopyCaseInsensitive(CacheInstance.GlobalCatalogCache);
            }
            if (CacheInstance.ValueToIdCache != null)
            {
                CacheInstance.ValueToIdCache = CopyCaseInsensitive(CacheInstance.ValueToIdCache);
            }
        }

        /// <summary>
        ///     Copies <paramref name="source"/> into a new <see cref="ConcurrentDictionary{TKey,TValue}"/> keyed
        ///     by <see cref="StringComparer.OrdinalIgnoreCase"/>. Entries are added with TryAdd so keys that
        ///     collide only by case (introduced before the case-insensitive invariant was reapplied) are
        ///     silently dropped — first writer wins — rather than throwing from the constructor.
        /// </summary>
        private static ConcurrentDictionary<string, TValue> CopyCaseInsensitive<TValue>(
            ConcurrentDictionary<string, TValue> source)
        {
            var copy = new ConcurrentDictionary<string, TValue>(StringComparer.OrdinalIgnoreCase);
            foreach (var kvp in source)
            {
                copy.TryAdd(kvp.Key, kvp.Value);
            }
            return copy;
        }

        /// <summary>
        ///     Gets stats from the currently loaded cache
        /// </summary>
        /// <returns></returns>
        public string GetCacheStats()
        {
            try
            {
                return
                    $"{IdToTypeCache.Count} ID to type mappings.\n {ValueToIdCache.Count} name to SID mappings.\n {MachineSidCache.Count} machine sid mappings.\n {SIDToDomainCache.Count} sid to domain mappings.\n {GlobalCatalogCache.Count} global catalog mappings.";
            }
            catch
            {
                return "";
            }
        }

        /// <summary>
        ///     Returns the currently loaded cache instance
        /// </summary>
        /// <returns></returns>
        public static Cache GetCacheInstance()
        {
            return CacheInstance;
        }

        private static void CreateMissingDictionaries()
        {
            CacheInstance ??= new Cache();
            CacheInstance.IdToTypeCache ??= new ConcurrentDictionary<string, Label>();
            CacheInstance.GlobalCatalogCache ??=
                new ConcurrentDictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
            CacheInstance.MachineSidCache ??= new ConcurrentDictionary<string, string>();
            CacheInstance.SIDToDomainCache ??=
                new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            CacheInstance.ValueToIdCache ??=
                new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
    }
}