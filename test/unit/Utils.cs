using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace CommonLibTest
{
    public static class Utils
    {
        internal static byte[] B64ToBytes(string base64)
        {
            return Convert.FromBase64String(base64);
        }

        internal static string B64ToString(string base64)
        {
            var b = B64ToBytes(base64);
            return Encoding.UTF8.GetString(b);
        }
    }

    internal static class Extensions
    {
        public static async Task<T[]> ToArrayAsync<T>(this IAsyncEnumerable<T> items)
        {
            var results = new List<T>();
            await foreach (var item in items
                               .ConfigureAwait(false))
                results.Add(item);
            return results.ToArray();
        }
        
        internal static bool IsArray(this object obj)
        {
            var valueType = obj?.GetType();
            if (valueType == null)
                return false;
            return valueType.IsArray;
        }

        internal static IAsyncEnumerable<T> ToAsyncEnumerable<T>(this IEnumerable<T> source) {
            return source switch {
                ICollection<T> collection => new IAsyncEnumerableCollectionAdapter<T>(collection),
                _ => null
            };
        }

        private sealed class IAsyncEnumerableCollectionAdapter<T> : IAsyncEnumerable<T> {
            private readonly IAsyncEnumerator<T> _enumerator;

            public IAsyncEnumerableCollectionAdapter(ICollection<T> source) {
                _enumerator = new IAsyncEnumeratorCollectionAdapter<T>(source);
            }
            public IAsyncEnumerator<T> GetAsyncEnumerator(CancellationToken cancellationToken = new CancellationToken()) {
                return _enumerator;
            }
        }

        private sealed class IAsyncEnumeratorCollectionAdapter<T> : IAsyncEnumerator<T> {
            private readonly IEnumerable<T> _source;
            private IEnumerator<T> _enumerator;

            public IAsyncEnumeratorCollectionAdapter(ICollection<T> source) {
                _source = source;
            }
            
            public ValueTask DisposeAsync() {
                _enumerator = null;
                return ValueTask.CompletedTask;
            }

            public ValueTask<bool> MoveNextAsync() {
                if (_enumerator == null) {
                    _enumerator = _source.GetEnumerator();
                }
                return ValueTask.FromResult(_enumerator.MoveNext());
            }

            public T Current => _enumerator.Current;
        }
    }

    public sealed class WindowsOnlyFact : FactAttribute
    {
        public WindowsOnlyFact()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) Skip = "Ignore on non-Windows platforms";
        }
    }

    public sealed class WindowsOnlyTheory : TheoryAttribute {
        public WindowsOnlyTheory() {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) Skip = "Ignore on non-Windows platforms";
        }
    }
}