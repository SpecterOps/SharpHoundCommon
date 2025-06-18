using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;

namespace SharpHoundCommonLib;

public class DirectoryEntryWrapper : IDirectoryObject {
    private readonly DirectoryEntry _entry;

    public DirectoryEntryWrapper(DirectoryEntry entry) {
        _entry = entry;
    }
    
    public bool TryGetDistinguishedName(out string value) {
        return TryGetProperty(LDAPProperties.DistinguishedName, out value);
    }

    private bool CheckCache(string propertyName) {
        try {
            // Blocking External Call
            if (!_entry.Properties.Contains(propertyName))
                _entry.RefreshCache(new[] { propertyName });
            
            // Blocking External Call
            return _entry.Properties.Contains(propertyName);
        }
        catch {
            return false;
        }
    }

    public bool TryGetProperty(string propertyName, out string value) {
        value = string.Empty;
        if (!CheckCache(propertyName)) {
            return false;
        }
        
        // Blocking External Call
        var s = _entry.Properties[propertyName].Value;
        value = s switch {
            string st => st,
            int i => i.ToString(),
            _ => null
        };

        return value != null;
    }

    public bool TryGetByteProperty(string propertyName, out byte[] value) {
        value = Array.Empty<byte>();
        if (!CheckCache(propertyName)) {
            return false;
        }
        
        // Blocking External Call
        var prop = _entry.Properties[propertyName].Value;
        if (prop is not byte[] b) return false;
        value = b;
        return true;
    }

    public bool TryGetArrayProperty(string propertyName, out string[] value) {
        value = Array.Empty<string>();
        if (!CheckCache(propertyName)) {
            return false;
        }

        var dest = new List<string>();
        // Blocking External Call
        foreach (var val in _entry.Properties[propertyName]) {
            if (val is string s) {
                dest.Add(s);
            }
        }

        value = dest.ToArray();
        return true;
    }

    public bool TryGetByteArrayProperty(string propertyName, out byte[][] value) {
        value = Array.Empty<byte[]>();
        if (!CheckCache(propertyName)) {
            return false;
        }

        // Blocking External Call
        var raw = _entry.Properties[propertyName].Value;
        if (raw is not byte[][] b) {
            return false;
        }
        value = b;
        return true;
    }

    public bool TryGetLongProperty(string propertyName, out long value) {
        value = 0;
        if (!CheckCache(propertyName)) return false;

        if (!TryGetProperty(propertyName, out var s)) {
            return false;
        }

        return long.TryParse(s, out value);
    }

    public bool TryGetCertificateArrayProperty(string propertyName, out X509Certificate2[] value) {
        value = Array.Empty<X509Certificate2>();
        if (!TryGetByteArrayProperty(propertyName, out var bytes)) {
            return false;
        }

        if (bytes.Length == 0) {
            return true;
        }
        
        var result = new List<X509Certificate2>();

        foreach (var b in bytes) {
            try {
                var cert = new X509Certificate2(b);
                result.Add(cert);
            }
            catch {
                //pass
            }
        }

        value = result.ToArray();
        return true;
    }

    public bool TryGetSecurityIdentifier(out string securityIdentifier) {
        securityIdentifier = string.Empty;
        if (!CheckCache(LDAPProperties.ObjectSID)) {
            return false;
        }

        // Blocking External Call
        var raw = _entry.Properties[LDAPProperties.ObjectSID][0];
        try {
            securityIdentifier = raw switch {
                byte[] b => new SecurityIdentifier(b, 0).ToString(),
                string st => new SecurityIdentifier(Encoding.ASCII.GetBytes(st), 0).ToString(),
                _ => default
            };

            return securityIdentifier != default;
        }
        catch {
            return false;
        }
    }

    public bool TryGetGuid(out string guid) {
        guid = string.Empty;
        if (!TryGetByteProperty(LDAPProperties.ObjectGUID, out var raw)) {
            return false;
        }

        try {
            guid = new Guid(raw).ToString().ToUpper();
            return true;
        } catch {
            return false;
        }
    }

    public string GetProperty(string propertyName) {
        CheckCache(propertyName);
        // Blocking External Call
        return _entry.Properties[propertyName].Value as string;
    }

    public byte[] GetByteProperty(string propertyName) {
        CheckCache(propertyName);
        // Blocking External Call
        return _entry.Properties[propertyName].Value as byte[];
    }

    public int PropertyCount(string propertyName) {
        if (!CheckCache(propertyName)) {
            return 0;
        }
        
        // Blocking External Call
        var prop = _entry.Properties[propertyName];
        return prop.Count;
        
    }

    public IEnumerable<string> PropertyNames() {
        // Blocking External Call
        foreach (var property in _entry.Properties.PropertyNames)
            yield return property.ToString().ToLower();
    }
}