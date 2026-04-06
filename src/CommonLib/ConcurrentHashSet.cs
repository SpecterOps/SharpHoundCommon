using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace SharpHoundCommonLib;

/// <summary>
/// A concurrent implementation of a hashset using a ConcurrentDictionary as the backing structure.
/// </summary>
public class ConcurrentHashSet : IDisposable{
    private ConcurrentDictionary<string, byte> _backingDictionary;

    public ConcurrentHashSet() {
        _backingDictionary = new ConcurrentDictionary<string, byte>();
    }
    
    public ConcurrentHashSet(StringComparer comparison) {
        _backingDictionary = new ConcurrentDictionary<string, byte>(comparison);
    }

    /// <summary>
    /// Attempts to add an item to the set. Returns true if adding was successful, false otherwise
    /// </summary>
    /// <param name="item"></param>
    /// <returns></returns>
    public bool Add(string item) {
        return _backingDictionary.TryAdd(item, byte.MinValue);
    }

    /// <summary>
    /// Attempts to remove an item from the set. Returns true of removing was successful, false otherwise
    /// </summary>
    /// <param name="item"></param>
    /// <returns></returns>
    public bool Remove(string item) {
        return _backingDictionary.TryRemove(item, out _);
    }

    /// <summary>
    /// Checks if the given item is in the set
    /// </summary>
    /// <param name="item"></param>
    /// <returns></returns>
    public bool Contains(string item) {
        return _backingDictionary.ContainsKey(item);
    }

    /// <summary>
    /// Returns all values in the set
    /// </summary>
    /// <returns></returns>
    public IEnumerable<string> Values() {
        return _backingDictionary.Keys;
    }

    public void Clear() {
        _backingDictionary.Clear();
    }

    public void Dispose() {
        _backingDictionary = null;
        GC.SuppressFinalize(this);
    }
    
}