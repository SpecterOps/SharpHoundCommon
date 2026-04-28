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
    }
}
