using System.Collections.Generic;

namespace SharpHoundCommonLib;

/// <summary>
/// Thread-safe registry of known domain controller SIDs, shared across all LdapUtils instances.
/// Extracted from LdapUtils to give DC tracking a single, focused home.
/// </summary>
internal class DomainControllerRegistry {
    // Static backing store intentionally mirrors the original LdapUtils static field so that
    // cross-instance visibility is preserved (same behaviour as before extraction).
    private static ConcurrentHashSet _domainControllers = new(System.StringComparer.OrdinalIgnoreCase);

    /// <summary>Adds a SID to the registry. No-op if already present.</summary>
    public void Add(string sid) => _domainControllers.Add(sid);

    /// <summary>Returns true if the SID is a known domain controller.</summary>
    public bool Contains(string sid) => _domainControllers.Contains(sid);

    /// <summary>Returns all registered domain controller SIDs.</summary>
    public IEnumerable<string> Values() => _domainControllers.Values();

    /// <summary>
    /// Resets the registry to an empty state.
    /// Called by <see cref="LdapUtils.ResetUtils"/> to support test isolation.
    /// </summary>
    public void Reset() {
        _domainControllers = new ConcurrentHashSet(System.StringComparer.OrdinalIgnoreCase);
    }
}
