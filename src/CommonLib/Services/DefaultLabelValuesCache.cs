using System;
using System.Collections.Generic;
using SharpHoundCommonLib.Interfaces;

namespace SharpHoundCommonLib.Services;

public sealed class DefaultLabelValuesCache : ILabelValuesCache {
    private readonly Dictionary<string, string[]> _cache = new();
    
    private readonly object _lock = new();
    private const char Separator = '\u001F'; // ascii unit separator

    public string[] Intern(string[] values) {
        if (values == null || values.Length == 0) {
            return [];
        }

        var key = MakeKey(values);

        lock (_lock) {
            if (_cache.TryGetValue(key, out var existing))
                return existing;
            
            var copy = new string[values.Length];
            Array.Copy(values, copy, values.Length);
            _cache[key] = copy;
            return copy;
        }
    }

    private static string MakeKey(string[] values) {
        if (values.Length == 1)
            return values[0];
        
        return string.Join(Separator.ToString(), values);
    }


}