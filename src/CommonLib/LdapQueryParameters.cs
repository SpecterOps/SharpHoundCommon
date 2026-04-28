using System;
using System.DirectoryServices.Protocols;
using System.Threading;
using SharpHoundCommonLib.Enums;

namespace SharpHoundCommonLib;

public class LdapQueryParameters {
    private static int _queryIDIndex;
    private string _relativeSearchBase;
    private string _searchBase;

    public LdapQueryParameters() {
        QueryID = _queryIDIndex;
        Interlocked.Increment(ref _queryIDIndex);
    }

    public string LDAPFilter { get; set; }
    public SearchScope SearchScope { get; set; } = SearchScope.Subtree;
    public string[] Attributes { get; set; } = Array.Empty<string>();
    public string DomainName { get; set; }
    public bool GlobalCatalog { get; set; }
    public bool IncludeSecurityDescriptor { get; set; } = false;
    public bool IncludeDeleted { get; set; } = false;
    private int QueryID { get; }

    public string SearchBase {
        get => _searchBase;
        set {
            _relativeSearchBase = null;
            _searchBase = value;
        }
    }

    public string RelativeSearchBase {
        get => _relativeSearchBase;
        set {
            _relativeSearchBase = value;
            _searchBase = null;
        }
    }

    public NamingContext NamingContext { get; set; } = NamingContext.Default;

    public string GetQueryInfo() {
        return
            $"Query Information - Filter: {LDAPFilter}, Domain: {DomainName}, GlobalCatalog: {GlobalCatalog}, ADSPath: {SearchBase}, ID: {QueryID}";
    }
}