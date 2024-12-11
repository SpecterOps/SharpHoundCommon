using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;

namespace SharpHoundCommonLib
{
    public static class Extensions
    {
        private static readonly ILogger Log;

        static Extensions()
        {
            Log = Logging.LogProvider.CreateLogger("Extensions");
        }
        
        public static async Task<List<T>> ToListAsync<T>(this IAsyncEnumerable<T> items)
        {
            if (items == null) {
                return new List<T>();
            }
            var results = new List<T>();
            await foreach (var item in items
                               .ConfigureAwait(false))
                results.Add(item);
            return results;
        }
        
        public static async Task<T[]> ToArrayAsync<T>(this IAsyncEnumerable<T> items)
        {
            if (items == null) {
                return Array.Empty<T>();
            }
            var results = new List<T>();
            await foreach (var item in items
                               .ConfigureAwait(false))
                results.Add(item);
            return results.ToArray();
        }

        public static async Task<T> FirstOrDefaultAsync<T>(this IAsyncEnumerable<T> source,
            CancellationToken cancellationToken = default) {
            if (source == null) {
                return default;
            }

            await using (var enumerator = source.GetAsyncEnumerator(cancellationToken)) {
                var first = await enumerator.MoveNextAsync() ? enumerator.Current : default;
                return first;
            }
        }
        
        public static async Task<T> FirstOrDefaultAsync<T>(this IAsyncEnumerable<T> source, T defaultValue,
            CancellationToken cancellationToken = default) {
            if (source == null) {
                return defaultValue;
            }

            await using (var enumerator = source.GetAsyncEnumerator(cancellationToken)) {
                var first = await enumerator.MoveNextAsync() ? enumerator.Current : defaultValue;
                return first;
            }
        }
        
        public static IAsyncEnumerable<T> DefaultIfEmpty<T>(this IAsyncEnumerable<T> source,
            T defaultValue, CancellationToken cancellationToken = default) {
            return new DefaultIfEmptyAsyncEnumerable<T>(source, defaultValue);
        }

        private sealed class DefaultIfEmptyAsyncEnumerable<T> : IAsyncEnumerable<T> {
            private readonly DefaultIfEmptyAsyncEnumerator<T> _enumerator;
            public DefaultIfEmptyAsyncEnumerable(IAsyncEnumerable<T> source, T defaultValue) {
                _enumerator = new DefaultIfEmptyAsyncEnumerator<T>(source, defaultValue);
            }
            public IAsyncEnumerator<T> GetAsyncEnumerator(CancellationToken cancellationToken = new CancellationToken()) {
                return _enumerator;
            }
        }

        private sealed class DefaultIfEmptyAsyncEnumerator<T> : IAsyncEnumerator<T> {
            private readonly IAsyncEnumerable<T> _source;
            private readonly T _defaultValue;
            private T _current;
            private bool _enumeratorDisposed;

            private IAsyncEnumerator<T> _enumerator;
            
            public DefaultIfEmptyAsyncEnumerator(IAsyncEnumerable<T> source, T defaultValue) {
                _source = source;
                _defaultValue = defaultValue;
            }
            
            public async ValueTask DisposeAsync() {
                _enumeratorDisposed = true;
                if (_enumerator != null) {
                    await _enumerator.DisposeAsync().ConfigureAwait(false);
                    _enumerator = null;
                }
            }

            public async ValueTask<bool> MoveNextAsync() {
                if (_enumeratorDisposed) {
                    return false;
                }
                _enumerator ??= _source.GetAsyncEnumerator();

                if (await _enumerator.MoveNextAsync().ConfigureAwait(false)) {
                    _current = _enumerator.Current;
                    return true;
                }

                _current = _defaultValue;
                await DisposeAsync().ConfigureAwait(false);
                return true;
            }

            public T Current => _current;
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
                return new ValueTask(Task.CompletedTask);
            }

            public ValueTask<bool> MoveNextAsync() {
                if (_enumerator == null) {
                    _enumerator = _source.GetEnumerator();
                }
                return new ValueTask<bool>(_enumerator.MoveNext());
            }

            public T Current => _enumerator.Current;
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
        
        /// <summary>
        ///     Returns true if any computer collection methods are set
        /// </summary>
        /// <param name="methods"></param>
        /// <returns></returns>
        public static bool IsComputerCollectionSet(this CollectionMethod methods) {
            const CollectionMethod test = CollectionMethod.ComputerOnly | CollectionMethod.LoggedOn | CollectionMethod.SmbInfo | CollectionMethod.SmbInfo;
            return (methods & test) != 0;
        }

        /// <summary>
        ///     Returns true if any local group collections are set
        /// </summary>
        /// <param name="methods"></param>
        /// <returns></returns>
        public static bool IsLocalGroupCollectionSet(this CollectionMethod methods)
        {
            return (methods & CollectionMethod.LocalGroups) != 0;
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
        
        public static IDirectoryObject ToDirectoryObject(this DirectoryEntry entry) {
            return new DirectoryEntryWrapper(entry);
        }
    }
}