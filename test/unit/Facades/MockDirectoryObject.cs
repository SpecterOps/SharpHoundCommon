using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;

namespace CommonLibTest.Facades;

public class MockDirectoryObject : IDirectoryObject {
    private readonly string _objectSID;
    private readonly string _objectGuid;
    public IDictionary Properties { get; set; }
    public string DistinguishedName { get; set; }

    public MockDirectoryObject(string distinguishedName, IDictionary properties, string sid = "", string guid = "") {
        DistinguishedName = distinguishedName;
        Properties = properties;
        _objectSID = sid;
        _objectGuid = guid;
    }
    
    public bool TryGetDistinguishedName(out string value) {
        value = DistinguishedName;
        return !string.IsNullOrWhiteSpace(DistinguishedName);
    }

    public bool TryGetProperty(string propertyName, out string value) {
        if (!Properties.Contains(propertyName)) {
            value = default;
            return false;
        }

        var temp = Properties[propertyName];

        switch (temp) {
            case string s:
                value = s;
                return true;
            case int i:
                value = i.ToString();
                return true;
            default:
                value = default;
                return false;
        }
    }

    public bool TryGetByteProperty(string propertyName, out byte[] value) {
        if (!Properties.Contains(propertyName)) {
            value = default;
            return false;
        }

        switch (Properties[propertyName]) {
            case string prop:
                value = Encoding.ASCII.GetBytes(prop);
                return true;
            case byte[] b:
                value = b;
                return true;
            default:
                value = default;
                return false;
        }
    }

    public bool TryGetArrayProperty(string propertyName, out string[] value) {
        if (!Properties.Contains(propertyName)) {
            value = Array.Empty<string>();
            return false;
        }

        var temp = Properties[propertyName];
        if (temp.IsArray()) {
            if (temp is string[] s) {
                value = s;
                return true;
            }
            value = Array.Empty<string>(); 
            return true;
        }

        value = Array.Empty<string>();
        return false;
    }

    public bool TryGetByteArrayProperty(string propertyName, out byte[][] value) {
        if (!Properties.Contains(propertyName)) {
            value = Array.Empty<byte[]>();
            return false;
        }

        if (Properties[propertyName] is byte[][] b) {
            value = b;
            return true;
        }

        value = default;
        return false;
    }

    public bool TryGetLongProperty(string propertyName, out long value) {
        if (!Properties.Contains(propertyName)) {
            value = default;
            return false;
        }

        switch (Properties[propertyName]) {
            case int i:
                value = i;
                return true;
            case string s when int.TryParse(s, out var val):
                value = val;
                return true;
            case long i:
                value = i;
                return true;
            default:
                value = 0;
                return false;
        }
    }

    public bool TryGetCertificateArrayProperty(string propertyName, out X509Certificate2[] value) {
        if (!TryGetByteArrayProperty(propertyName, out var b)) {
            value = [];
            return false;
        }

        value = b.Select(X509CertificateLoader.LoadCertificate).ToArray();
        return true;
    }

    public bool TryGetSecurityIdentifier(out string securityIdentifier) {
        securityIdentifier = _objectSID;
        return true;
    }

    public bool TryGetGuid(out string guid) {
        guid = _objectGuid;
        return true;
    }

    public string GetProperty(string propertyName) {
        return Properties[propertyName] as string;
    }

    public byte[] GetByteProperty(string propertyName) {
        return Properties[propertyName] as byte[];
    }

    public int PropertyCount(string propertyName) {
        if (!Properties.Contains(propertyName)) {
            return 0;
        }
        
        var property = Properties[propertyName];
        if (property.IsArray())
        {
            if (property is string[] s) {
                return s.Length;
            }

            if (property is byte[] b) {
                return b.Length;
            }

            return 0;
        }

        return 1;
    }

    public IEnumerable<string> PropertyNames() {
        foreach (var property in Properties.Keys) yield return property.ToString().ToLower();
    }
}