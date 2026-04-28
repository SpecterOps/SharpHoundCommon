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
        public void AddDomainSidMapping_NetBiosName_DoesNotPoisonSidToNameSlot()
        {
            // A NetBIOS-only write must not populate the SID->Name slot, because consumers of
            // that slot expect a DNS-shaped FQDN (LDAP base DN construction, server selection,
            // GetDomainInfoAsync hint resolution). Leaving the slot empty lets a later
            // FQDN-keyed write populate it correctly.
            Cache.SetCacheInstance(Cache.CreateNewCache());

            const string sid = "S-1-5-21-1212121212-3434343434-5656565656";
            const string netbios = "CONTOSO";

            Cache.AddDomainSidMapping(sid, netbios);

            Assert.False(Cache.GetDomainSidMapping(sid, out _));
            Assert.True(Cache.GetDomainSidMapping(netbios, out var resolvedSid));
            Assert.Equal(sid, resolvedSid);

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
    }
}
