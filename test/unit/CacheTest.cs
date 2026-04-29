using System;
using CommonLibTest.CollectionDefinitions;
using Newtonsoft.Json;
using SharpHoundCommonLib;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest
{
    [Collection(nameof(CacheTestCollectionDefinition))]
    public class CacheTest
    {
        private ITestOutputHelper _testOutputHelper;
        public CacheTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        [Fact]
        public void Cache_TestNewCache()
        {
            var cache = Cache.CreateNewCache();
            Assert.Equal(cache.CacheCreationVersion, new Version(1,0,0));
            var version = new Version(1, 0, 1);
            cache = Cache.CreateNewCache(version);
            var time = DateTime.Now.Date;
            Assert.Equal(cache.CacheCreationVersion, version);
            Assert.Equal(cache.CacheCreationDate, time);
        }

        [Fact]
        public void AddDomainSidMapping_WritesBothDirections()
        {
            Cache.SetCacheInstance(Cache.CreateNewCache());

            const string sid = "S-1-5-21-1111111111-2222222222-3333333333";
            const string name = "CONTOSO.LOCAL";

            Cache.AddDomainSidMapping(sid, name);

            Assert.True(Cache.GetDomainSidMapping(sid, out var resolvedName));
            Assert.Equal(name, resolvedName);
            Assert.True(Cache.GetDomainSidMapping(name, out var resolvedSid));
            Assert.Equal(sid, resolvedSid);

            Cache.SetCacheInstance(null);
        }

        [Fact]
        public void AddDomainSidMapping_BidirectionalRegardlessOfArgumentOrder()
        {
            Cache.SetCacheInstance(Cache.CreateNewCache());

            const string sid = "S-1-5-21-4444444444-5555555555-6666666666";
            const string name = "FABRIKAM.LOCAL";

            // Reverse argument order: caller passes (name, sid) instead of (sid, name).
            Cache.AddDomainSidMapping(name, sid);

            Assert.True(Cache.GetDomainSidMapping(sid, out var resolvedName));
            Assert.Equal(name, resolvedName);
            Assert.True(Cache.GetDomainSidMapping(name, out var resolvedSid));
            Assert.Equal(sid, resolvedSid);

            Cache.SetCacheInstance(null);
        }

        [Fact]
        public void AddDomainSidMapping_LookupIsCaseInsensitive()
        {
            Cache.SetCacheInstance(Cache.CreateNewCache());

            const string sid = "S-1-5-21-7777777777-8888888888-9999999999";
            const string name = "CONTOSO.LOCAL";

            Cache.AddDomainSidMapping(sid, name);

            Assert.True(Cache.GetDomainSidMapping("contoso.local", out var resolvedSid));
            Assert.Equal(sid, resolvedSid);

            Cache.SetCacheInstance(null);
        }

        [Fact]
        public void AddDomainSidMapping_FirstWriterWins()
        {
            Cache.SetCacheInstance(Cache.CreateNewCache());

            const string sid = "S-1-5-21-1010101010-2020202020-3030303030";
            const string firstName = "FIRST.LOCAL";
            const string secondName = "SECOND.LOCAL";

            Cache.AddDomainSidMapping(sid, firstName);
            Cache.AddDomainSidMapping(sid, secondName);

            Assert.True(Cache.GetDomainSidMapping(sid, out var resolvedName));
            Assert.Equal(firstName, resolvedName);
            // Reverse mapping for the first name was also written; the second name's reverse
            // entry was not because TryAdd preserves the existing sid->firstName entry only,
            // but secondName is itself a fresh key.
            Assert.True(Cache.GetDomainSidMapping(firstName, out var resolvedSid));
            Assert.Equal(sid, resolvedSid);

            Cache.SetCacheInstance(null);
        }

        [Theory]
        [InlineData(null, "CONTOSO.LOCAL")]
        [InlineData("S-1-5-21-1-2-3", null)]
        [InlineData("", "CONTOSO.LOCAL")]
        [InlineData("S-1-5-21-1-2-3", "")]
        [InlineData(null, null)]
        public void AddDomainSidMapping_NullOrEmptyArgumentsAreIgnored(string key, string value)
        {
            Cache.SetCacheInstance(Cache.CreateNewCache());

            Cache.AddDomainSidMapping(key, value);

            if (!string.IsNullOrEmpty(key))
            {
                Assert.False(Cache.GetDomainSidMapping(key, out _));
            }
            if (!string.IsNullOrEmpty(value))
            {
                Assert.False(Cache.GetDomainSidMapping(value, out _));
            }

            Cache.SetCacheInstance(null);
        }

        [Fact]
        public void AddDomainSidMapping_NetBiosName_ReverseArgumentOrder_DoesNotPoisonSidToNameSlot()
        {
            // Same poisoning vector with arguments reversed: AddDomainSidMapping(netbios, sid).
            Cache.SetCacheInstance(Cache.CreateNewCache());

            const string sid = "S-1-5-21-7878787878-9090909090-1212121212";
            const string netbios = "FABRIKAM";

            Cache.AddDomainSidMapping(netbios, sid);

            Assert.False(Cache.GetDomainSidMapping(sid, out _));
            Assert.True(Cache.GetDomainSidMapping(netbios, out var resolvedSid));
            Assert.Equal(sid, resolvedSid);

            Cache.SetCacheInstance(null);
        }

        [Theory]
        [InlineData("10.0.0.1")]                            // IPv4 literal
        [InlineData("192.168.1.100")]                       // IPv4 literal
        [InlineData("contoso.")]                            // trailing-dot artifact
        [InlineData(".contoso.com")]                        // leading-dot junk
        [InlineData("contoso..com")]                        // empty middle label
        [InlineData("-contoso.com")]                        // leading hyphen
        [InlineData("contoso-.com")]                        // trailing hyphen on label
        [InlineData("contoso.com-")]                        // trailing hyphen on FQDN
        [InlineData("contoso.local!")]                      // invalid character
        [InlineData("contoso .local")]                      // embedded space
        [InlineData("CORP")]                                // single-label (ambiguous with NetBIOS)
        public void AddDomainSidMapping_NonDnsShapedName_DoesNotPoisonSidToNameSlot(string badName)
        {
            // Anything that isn't unambiguously an RFC-1035 multi-label FQDN gets rejected from
            // the SID->Name slot. IPv4 literals and malformed label sets are the legacy-environment
            // vectors that the old IndexOf('.') heuristic let through. NetBIOS names that happen
            // to contain a dot (e.g. "CONTOSO.OLD") are syntactically indistinguishable from real
            // FQDNs and remain an unavoidable false-positive of any pure-syntax check.
            Cache.SetCacheInstance(Cache.CreateNewCache());

            const string sid = "S-1-5-21-1010101010-2020202020-3030303030";
            Cache.AddDomainSidMapping(sid, badName);

            Assert.False(Cache.GetDomainSidMapping(sid, out _));
            Assert.True(Cache.GetDomainSidMapping(badName, out var resolvedSid));
            Assert.Equal(sid, resolvedSid);

            Cache.SetCacheInstance(null);
        }

        [Theory]
        [InlineData("contoso.local")]                       // typical AD FQDN
        [InlineData("CONTOSO.LOCAL")]                       // upper-case
        [InlineData("sub.contoso.local")]                   // 3 labels
        [InlineData("a.b.c.d.e")]                           // 5 labels (rules out 4-label IPv4 collision)
        [InlineData("dc-01.contoso.local")]                 // mid-label hyphen
        [InlineData("123abc.contoso.local")]                // leading digit per RFC 1123
        public void AddDomainSidMapping_DnsShapedName_PopulatesSidToNameSlot(string fqdn)
        {
            // Positive coverage for the tightened heuristic: legitimate FQDNs still populate
            // both directions of the cache.
            Cache.SetCacheInstance(Cache.CreateNewCache());

            const string sid = "S-1-5-21-4040404040-5050505050-6060606060";
            Cache.AddDomainSidMapping(sid, fqdn);

            Assert.True(Cache.GetDomainSidMapping(sid, out var resolvedName));
            Assert.Equal(fqdn, resolvedName);
            Assert.True(Cache.GetDomainSidMapping(fqdn, out var resolvedSid));
            Assert.Equal(sid, resolvedSid);

            Cache.SetCacheInstance(null);
        }

        [Fact]
        public void AddDomainSidMapping_NetBiosThenFqdn_FqdnPopulatesSidToNameSlot()
        {
            // After a NetBIOS-keyed write leaves the SID->Name slot empty, a subsequent
            // FQDN-keyed write must fill it with the canonical DNS name. This is the key
            // behavior that makes the gating safe: the slot stays available for the richer
            // resolver to populate.
            Cache.SetCacheInstance(Cache.CreateNewCache());

            const string sid = "S-1-5-21-3434343434-5656565656-7878787878";
            const string netbios = "CONTOSO";
            const string fqdn = "CONTOSO.LOCAL";

            Cache.AddDomainSidMapping(netbios, sid);
            Cache.AddDomainSidMapping(fqdn, sid);

            Assert.True(Cache.GetDomainSidMapping(sid, out var resolvedName));
            Assert.Equal(fqdn, resolvedName);
            Assert.True(Cache.GetDomainSidMapping(netbios, out var resolvedFromNetbios));
            Assert.Equal(sid, resolvedFromNetbios);
            Assert.True(Cache.GetDomainSidMapping(fqdn, out var resolvedFromFqdn));
            Assert.Equal(sid, resolvedFromFqdn);

            Cache.SetCacheInstance(null);
        }

        [Fact]
        public void SetCacheInstance_AfterDeserialization_RestoresCaseInsensitiveSidToDomain()
        {
            // Simulate the load-from-disk scenario by round-tripping with
            // ObjectCreationHandling.Replace, which forces the deserializer to assign a fresh
            // ConcurrentDictionary via the property setter rather than reusing the one created
            // by the private parameterless constructor. This reproduces the behavior of
            // serializers (DataContractSerializer, System.Text.Json) that always replace via
            // setters and therefore drop the OrdinalIgnoreCase comparer.
            var original = Cache.CreateNewCache();
            Cache.SetCacheInstance(original);
            Cache.AddDomainSidMapping("S-1-5-21-1-2-3", "CONTOSO.LOCAL");

            var json = JsonConvert.SerializeObject(original);
            var settings = new JsonSerializerSettings
            {
                ObjectCreationHandling = ObjectCreationHandling.Replace
            };
            var deserialized = JsonConvert.DeserializeObject<Cache>(json, settings);

            // Sanity: the freshly deserialized dictionary is case-sensitive - a differently
            // cased key misses against the inner dict directly. Proves the test reproduces
            // the regression the rewrap is fixing.
            Assert.False(deserialized.SIDToDomainCache.TryGetValue("contoso.local", out _));

            Cache.SetCacheInstance(deserialized);

            Assert.True(Cache.GetDomainSidMapping("contoso.local", out var resolvedSid));
            Assert.Equal("S-1-5-21-1-2-3", resolvedSid);
            Assert.True(Cache.GetDomainSidMapping("s-1-5-21-1-2-3", out var resolvedName));
            Assert.Equal("CONTOSO.LOCAL", resolvedName);

            Cache.SetCacheInstance(null);
        }

        [Fact]
        public void SetCacheInstance_AfterDeserialization_RestoresCaseInsensitiveGlobalCatalog()
        {
            var original = Cache.CreateNewCache();
            Cache.SetCacheInstance(original);
            Cache.AddGCCache("CONTOSO.LOCAL", new[] { "gc1.contoso.local", "gc2.contoso.local" });

            var json = JsonConvert.SerializeObject(original);
            var settings = new JsonSerializerSettings
            {
                ObjectCreationHandling = ObjectCreationHandling.Replace
            };
            var deserialized = JsonConvert.DeserializeObject<Cache>(json, settings);

            Assert.False(deserialized.GlobalCatalogCache.TryGetValue("contoso.local", out _));

            Cache.SetCacheInstance(deserialized);

            Assert.True(Cache.GetGCCache("contoso.local", out var gcs));
            Assert.Equal(2, gcs.Length);

            Cache.SetCacheInstance(null);
        }

        [Theory]
        [InlineData("Administrator", "CONTOSO.LOCAL", "administrator", "contoso.local")]
        [InlineData("administrator", "contoso.local", "ADMINISTRATOR", "CONTOSO.LOCAL")]
        [InlineData("HOST01$", "contoso.local", "host01$", "CONTOSO.LOCAL")]
        public void AddPrefixedValue_LookupIsCaseInsensitiveOnBothComponents(
            string writeName, string writeDomain, string readName, string readDomain)
        {
            // samAccountName uses caseIgnoreString syntax in AD and DNS domain names are
            // case-insensitive; the cache must reflect that to avoid fragmented entries
            // and redundant LDAP queries.
            Cache.SetCacheInstance(Cache.CreateNewCache());

            Cache.AddPrefixedValue(writeName, writeDomain, "S-1-5-21-1-2-3-1001");

            Assert.True(Cache.GetPrefixedValue(readName, readDomain, out var resolved));
            Assert.Equal("S-1-5-21-1-2-3-1001", resolved);

            Cache.SetCacheInstance(null);
        }

        [Fact]
        public void SetCacheInstance_AfterDeserialization_RestoresCaseInsensitiveValueToId()
        {
            var original = Cache.CreateNewCache();
            Cache.SetCacheInstance(original);
            Cache.AddPrefixedValue("Administrator", "CONTOSO.LOCAL", "S-1-5-21-1-2-3-500");

            var json = JsonConvert.SerializeObject(original);
            var settings = new JsonSerializerSettings
            {
                ObjectCreationHandling = ObjectCreationHandling.Replace
            };
            var deserialized = JsonConvert.DeserializeObject<Cache>(json, settings);

            Assert.False(deserialized.ValueToIdCache.TryGetValue("administrator|contoso.local", out _));

            Cache.SetCacheInstance(deserialized);

            Assert.True(Cache.GetPrefixedValue("administrator", "contoso.local", out var resolved));
            Assert.Equal("S-1-5-21-1-2-3-500", resolved);

            Cache.SetCacheInstance(null);
        }

        [Fact]
        public void SetCacheInstance_AfterDeserialization_HealsCaseCollidingKeys()
        {
            // A persisted cache produced before the case-insensitive invariant was applied
            // (or hand-edited / corrupted on disk) can contain two keys that differ only by
            // case in the same dictionary. Deserialization rebuilds a case-sensitive
            // ConcurrentDictionary, so both keys survive the round trip. The rewrap must
            // tolerate the collision (first writer wins) instead of throwing from the
            // ConcurrentDictionary(IEnumerable, IEqualityComparer) constructor.
            // Each dictionary contains a pair of keys differing only by case. In a
            // case-sensitive ConcurrentDictionary (what the deserializer rebuilds) both keys
            // survive; rewrapping with OrdinalIgnoreCase against that source is the path that
            // previously threw ArgumentException.
            const string json = @"{
                ""SIDToDomainCache"": {
                    ""CONTOSO.LOCAL"": ""S-1-5-21-1-2-3"",
                    ""contoso.local"": ""S-1-5-21-1-2-3""
                },
                ""GlobalCatalogCache"": {
                    ""CONTOSO.LOCAL"": [""gc1.contoso.local""],
                    ""contoso.local"": [""gc1.contoso.local""]
                },
                ""ValueToIdCache"": {
                    ""Administrator|CONTOSO.LOCAL"": ""S-1-5-21-1-2-3-500"",
                    ""administrator|contoso.local"": ""S-1-5-21-1-2-3-500""
                },
                ""IdToTypeCache"": {},
                ""MachineSidCache"": {},
                ""CacheCreationDate"": ""0001-01-01T00:00:00"",
                ""CacheCreationVersion"": ""1.0.0""
            }";
            var settings = new JsonSerializerSettings
            {
                ObjectCreationHandling = ObjectCreationHandling.Replace
            };
            var deserialized = JsonConvert.DeserializeObject<Cache>(json, settings);

            // Sanity: the deserialized dictionaries actually contain the colliding keys.
            // Without this, the test would not exercise the constructor's duplicate-key path.
            Assert.Equal(2, deserialized.SIDToDomainCache.Count);
            Assert.Equal(2, deserialized.GlobalCatalogCache.Count);
            Assert.Equal(2, deserialized.ValueToIdCache.Count);

            // Pre-fix this call threw ArgumentException from the rewrap constructor.
            var ex = Record.Exception(() => Cache.SetCacheInstance(deserialized));
            Assert.Null(ex);

            // Each cache collapses to a single entry per case-insensitive key (first wins).
            Assert.Single(deserialized.SIDToDomainCache);
            Assert.Single(deserialized.GlobalCatalogCache);
            Assert.Single(deserialized.ValueToIdCache);

            // Lookups succeed under either casing after the rewrap.
            Assert.True(Cache.GetDomainSidMapping("contoso.local", out var resolvedSid));
            Assert.Equal("S-1-5-21-1-2-3", resolvedSid);
            Assert.True(Cache.GetGCCache("contoso.local", out var gcs));
            Assert.Single(gcs);
            Assert.True(Cache.GetPrefixedValue("administrator", "contoso.local", out var resolvedId));
            Assert.Equal("S-1-5-21-1-2-3-500", resolvedId);

            Cache.SetCacheInstance(null);
        }
    }
}
