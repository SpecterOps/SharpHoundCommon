using System.Collections.Concurrent;
using System.Linq;
using System.Threading.Tasks;
using SharpHoundCommonLib.Services;
using Xunit;

namespace CommonLibTest;

public class DefaultLabelValuesCacheTests {
    
    [Theory]
    [InlineData(new[] {"value"}, "value")]
    [InlineData(new string[] {}, "")]
    [InlineData(new[] {"value1", "value2"}, "value1\u001Fvalue2")]
    [InlineData(new[] {"value1", "value2", "value3"}, "value1\u001Fvalue2\u001Fvalue3")]
    public void MakeKey_Returns_Proper_Key(string[] labelValues, string expectedKey) {
        // act
        var key = DefaultLabelValuesCache.MakeKey(labelValues);
        
        // assert
        Assert.Equal(expectedKey, key);
    }

    [Fact]
    public void Intern_Retrieves_Existing_LabelValues() {
        // setup
        string[] values1 = ["value1", "value2"];
        string[] values2 = ["value1", "value2"];
        var cache = new DefaultLabelValuesCache();
        
        // act
        cache.Intern(values1);
        cache.Intern(values2);

        // assert
        Assert.NotEmpty(cache._cache);
        Assert.Single(cache._cache);
    }

    [Fact]
    public void Empty_Intern_Returns_Empty_Array() {
       // setup
       var cache = new DefaultLabelValuesCache();
       
       // act
       var ret = cache.Intern([]);
       
       // assert
       Assert.Empty(ret);
    }
    
    [Fact]
    public async Task LabelValuesCache_ReturnsSameReference_UnderConcurrency()
    {
        // setup
        var cache = new DefaultLabelValuesCache();
        const int threadCount = 16;
        const int iterationsPerThread = 10_000;
        var results = new ConcurrentBag<string[]>();
        var tasks = new Task[threadCount];

        for (var t = 0; t < threadCount; t++)
        {
            tasks[t] = Task.Run(() =>
            {
                for (var i = 0; i < iterationsPerThread; i++)
                {
                    var labels = cache.Intern(["GET", "200"]);
                    results.Add(labels);
                }
            });
        }

        // act
        await Task.WhenAll(tasks);

        // assert
        // Take the first reference
        var first = results.First();

        // Assert all references are identical
        foreach (var arr in results)
        {
            Assert.True(
                object.ReferenceEquals(first, arr),
                "Different label array instances were returned");
        }
    }

}