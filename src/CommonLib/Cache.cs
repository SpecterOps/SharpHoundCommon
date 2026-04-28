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

        private static bool LooksLikeDnsDomainName(string value)
        {
            return value != null && value.IndexOf('.') >= 0;
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
                CacheInstance.SIDToDomainCache = new ConcurrentDictionary<string, string>(
                    CacheInstance.SIDToDomainCache, StringComparer.OrdinalIgnoreCase);
            }
            if (CacheInstance.GlobalCatalogCache != null)
            {
                CacheInstance.GlobalCatalogCache = new ConcurrentDictionary<string, string[]>(
                    CacheInstance.GlobalCatalogCache, StringComparer.OrdinalIgnoreCase);
            }
            if (CacheInstance.ValueToIdCache != null)
            {
                CacheInstance.ValueToIdCache = new ConcurrentDictionary<string, string>(
                    CacheInstance.ValueToIdCache, StringComparer.OrdinalIgnoreCase);
            }
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