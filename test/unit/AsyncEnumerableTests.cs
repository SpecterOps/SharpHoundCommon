using System.Collections.Generic;
using System.Threading.Tasks;
using SharpHoundCommonLib;
using Xunit;

namespace CommonLibTest;

public class AsyncEnumerableTests {
    [Fact]
    public async Task AsyncEnumerable_DefaultIfEmpty_Empty() {
        var enumerable = AsyncEnumerable.Empty<int>().DefaultIfEmpty(1);
        var e = enumerable.GetAsyncEnumerator();
        var res = await e.MoveNextAsync();
        Assert.True(res);
        Assert.Equal(1, e.Current);
        Assert.False(await e.MoveNextAsync());
    }

    [Fact]
    public async Task AsyncEnumerable_FirstOrDefault() {
        var enumerable = AsyncEnumerable.Empty<int>();
        var res = await enumerable.FirstOrDefaultAsync();
        Assert.Equal(0, res);
    }
    
    [Fact]
    public async Task AsyncEnumerable_FirstOrDefault_WithDefault() {
        var enumerable = AsyncEnumerable.Empty<int>();
        var res = await enumerable.FirstOrDefaultAsync(10);
        Assert.Equal(10, res);
    }

    [Fact]
    public async Task AsyncEnumerable_CombinedOperators() {
        var enumerable = AsyncEnumerable.Empty<string>();
        var res = await enumerable.DefaultIfEmpty("abc").FirstOrDefaultAsync();
        Assert.Equal("abc", res);
    }

    [Fact]
    public async Task AsyncEnumerable_ToAsyncEnumerable() {
        var collection = new[] {
            "a", "b", "c"
        };
        
        var test = collection.ToAsyncEnumerable();

        var index = 0;
        await foreach (var item in test) {
            Assert.Equal(collection[index], item);
            index++;
        }
    }

    [Fact]
    public async Task AsyncEnumerable_FirstOrDefaultFunction() {
        var test = await TestFunc().FirstOrDefaultAsync();
        Assert.Equal("a", test);
    }
    
    [Fact]
    public async Task AsyncEnumerable_CombinedFunction() {
        var test = await TestFunc().DefaultIfEmpty("d").FirstOrDefaultAsync();
        Assert.Equal("a", test);
    }
    
    [Fact]
    public async Task AsyncEnumerable_FirstOrDefaultEmptyFunction() {
        var test = await EmptyFunc().FirstOrDefaultAsync();
        Assert.Null(test);
    }
    
    [Fact]
    public async Task AsyncEnumerable_CombinedEmptyFunction() {
        var test = await EmptyFunc().DefaultIfEmpty("d").FirstOrDefaultAsync();
        Assert.Equal("d", test);
    }

#pragma warning disable CS1998 //Async method lacks 'await' operators and will run synchronously, must be `async` to return IAsyncEnumerable
    private async IAsyncEnumerable<string> TestFunc() {
        var collection = new[] {
            "a", "b", "c"
        };

        foreach (var i in collection) {
            yield return i;
        }
    }

    private async IAsyncEnumerable<string> EmptyFunc() {
        yield break;
    }
#pragma warning restore CS1998
}