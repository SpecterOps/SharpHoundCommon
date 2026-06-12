using System;
using System.Collections.Generic;
using System.Security.Principal;
using CommonLibTest.Facades;
using SharpHoundCommonLib;
using SharpHoundCommonLib.DirectoryObjects;
using SharpHoundCommonLib.Enums;
using Xunit;

namespace CommonLibTest {
    public class DirectoryObjectTests {
        [Fact]
        public void Test_GetLabelIssuanceOIDObjects() {
            var attribs = new Dictionary<string, object> {
                { LDAPProperties.ObjectClass, new[] { "msPKI-Enterprise-Oid" } },
                { LDAPProperties.Flags, "2" }
            };

            var mock = new MockDirectoryObject("CN=Test,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration",
                attribs, "S-1-5-21-3130019616-2776909439-2417379446-500", "");

            var success = mock.GetLabel(out var label);
            Assert.True(success);
            Assert.Equal(Label.IssuancePolicy, label);

            mock = new MockDirectoryObject("CN=OID,CN=Public Key Services,CN=Services,CN=Configuration",
                attribs, "S-1-5-21-3130019616-2776909439-2417379446-500", "");
            success = mock.GetLabel(out label);
            Assert.True(success);
            Assert.Equal(Label.Container, label);
        }

        [Fact]
        public void Test_HasLaps() {
            var attribs = new Dictionary<string, object> {
                { LDAPProperties.LegacyLAPSExpirationTime, 12345 },
            };

            var mock = new MockDirectoryObject("abc", attribs, "", "");
            Assert.True(mock.HasLAPS());

            mock.Properties = new Dictionary<string, object> {
                { LDAPProperties.LAPSExpirationTime, 12345 },
            };

            Assert.True(mock.HasLAPS());

            mock.Properties = new Dictionary<string, object> {
                { LDAPProperties.Flags, 0 }
            };

            Assert.False(mock.HasLAPS());
        }

        [Fact]
        public void Test_IsDeleted() {
            var attribs = new Dictionary<string, object> {
                { LDAPProperties.IsDeleted, "true" },
            };

            var mock = new MockDirectoryObject("abc", attribs, "", "");
            Assert.True(mock.IsDeleted());

            mock.Properties = new Dictionary<string, object> {
                { LDAPProperties.IsDeleted, false },
            };
            Assert.False(mock.IsDeleted());

            mock.Properties = new Dictionary<string, object>();
            Assert.False(mock.IsDeleted());
        }

        [Fact]
        public void Test_IsMSA() {
            var attribs = new Dictionary<string, object> {
                { LDAPProperties.ObjectClass, new[] { "top", "msds-managedserviceaccount" } },
            };

            var mock = new MockDirectoryObject("abc", attribs, "", "");
            Assert.True(mock.IsMSA());
            Assert.False(mock.IsGMSA());

            mock.Properties = new Dictionary<string, object> {
                { LDAPProperties.ObjectClass, new[] { "top" } },
            };

            Assert.False(mock.IsMSA());
            Assert.False(mock.IsGMSA());

            mock.Properties = new Dictionary<string, object>();
            Assert.False(mock.IsGMSA());
            Assert.False(mock.IsMSA());
        }

        [Fact]
        public void Test_IsGMSA() {
            var attribs = new Dictionary<string, object> {
                { LDAPProperties.ObjectClass, new[] { "top", "msds-groupmanagedserviceaccount" } },
            };

            var mock = new MockDirectoryObject("abc", attribs, "", "");
            Assert.True(mock.IsGMSA());
            Assert.False(mock.IsMSA());

            mock.Properties = new Dictionary<string, object> {
                { LDAPProperties.ObjectClass, new[] { "top" } },
            };

            Assert.False(mock.IsGMSA());
            Assert.False(mock.IsMSA());

            mock.Properties = new Dictionary<string, object>();
            Assert.False(mock.IsGMSA());
            Assert.False(mock.IsMSA());
        }

        [Fact]
        public void Test_GetLabel_BadObjectID() {
            var attribs = new Dictionary<string, object> {
                { LDAPProperties.ObjectClass, new[] { "top", "msds-groupmanagedserviceaccount" } },
            };

            var mock = new MockDirectoryObject("abc", attribs, "", "");
            Assert.False(mock.GetLabel(out var label));
            Assert.Equal(Label.Base, label);
        }

        [Fact]
        public void Test_GetLabel_WellKnownAdministratorsObject() {
            var attribs = new Dictionary<string, object>() {
                { LDAPProperties.ObjectClass, new[] { "top" } },
                { LDAPProperties.Flags, "2" },
                { LDAPProperties.SAMAccountType, "805306368" }
            };

            var mock = new MockDirectoryObject("CN=Administrators,CN=BuiltIn,DC=Testlab,DC=Local", attribs,
                "S-1-5-32-544", new Guid().ToString());

            Assert.True(mock.GetLabel(out var label));
            Assert.Equal(Label.Group, label);
        }

        [Fact]
        public void Test_GetLabel_Computer_Objects() {
            var attribs = new Dictionary<string, object> {
                { LDAPProperties.ObjectClass, new[] { "top", "msds-groupmanagedserviceaccount" } },
                { LDAPProperties.Flags, "2" },
                { LDAPProperties.SAMAccountType, "805306369" }
            };

            var mock = new MockDirectoryObject("abc", attribs,
                "123456", new Guid().ToString());

            Assert.True(mock.GetLabel(out var label));
            Assert.Equal(Label.User, label);

            mock.Properties = new Dictionary<string, object> {
                { LDAPProperties.ObjectClass, new[] { "top", "msds-managedserviceaccount" } },
                { LDAPProperties.Flags, "2" },
                { LDAPProperties.SAMAccountType, "805306369" }
            };

            Assert.True(mock.GetLabel(out label));
            Assert.Equal(Label.User, label);

            mock.Properties = new Dictionary<string, object> {
                { LDAPProperties.ObjectClass, new[] { "top", "computer" } },
                { LDAPProperties.Flags, "2" },
                { LDAPProperties.SAMAccountType, "805306369" }
            };

            Assert.True(mock.GetLabel(out label));
            Assert.Equal(Label.Computer, label);
        }

        [Fact]
        public void Test_GetLabel_UserObjects() {
            var attribs = new Dictionary<string, object> {
                { LDAPProperties.ObjectClass, new[] { "top", "person" } },
                { LDAPProperties.SAMAccountType, "805306368" }
            };

            var mock = new MockDirectoryObject("abc", attribs,
                "123456", new Guid().ToString());
            Assert.True(mock.GetLabel(out var label));
            Assert.Equal(Label.User, label);
        }

        [Fact]
        public void Test_GetLabel_GPOObjects() {
            var attribs = new Dictionary<string, object> {
                { LDAPProperties.ObjectClass, new[] { "top", ObjectClass.GroupPolicyContainerClass } },
            };

            var mock = new MockDirectoryObject("abc", attribs,
                "123456", new Guid().ToString());
            Assert.True(mock.GetLabel(out var label));
            Assert.Equal(Label.GPO, label);
        }

        [Fact]
        public void Test_GetLabel_GroupObjects() {
            var attribs = new Dictionary<string, object> {
                { LDAPProperties.ObjectClass, new[] { "top" } },
                { LDAPProperties.SAMAccountType, "268435456" }
            };

            var mock = new MockDirectoryObject("abc", attribs,
                "123456", new Guid().ToString());
            Assert.True(mock.GetLabel(out var label));
            Assert.Equal(Label.Group, label);

            mock.Properties = new Dictionary<string, object> {
                { LDAPProperties.ObjectClass, new[] { "top" } },
                { LDAPProperties.SAMAccountType, "268435457" }
            };

            Assert.True(mock.GetLabel(out label));
            Assert.Equal(Label.Group, label);
        }

        [Fact]
        public void Test_GetLabel_DomainObjects() {
            var attribs = new Dictionary<string, object> {
                { LDAPProperties.ObjectClass, new[] { "top", ObjectClass.DomainClass } },
            };

            var mock = new MockDirectoryObject("abc", attribs,
                "123456", new Guid().ToString());
            Assert.True(mock.GetLabel(out var label));
            Assert.Equal(Label.Domain, label);
        }

        [Fact]
        public void Test_GetLabel_ContainerObjects() {
            var attribs = new Dictionary<string, object> {
                { LDAPProperties.ObjectClass, new[] { "top", ObjectClass.ContainerClass } },
            };

            var mock = new MockDirectoryObject("abc", attribs,
                "123456", new Guid().ToString());
            Assert.True(mock.GetLabel(out var label));
            Assert.Equal(Label.Container, label);
        }

        [Fact]
        public void Test_GetLabel_ConfigurationObjects() {
            var attribs = new Dictionary<string, object> {
                { LDAPProperties.ObjectClass, new[] { "top", ObjectClass.ConfigurationClass } },
            };

            var mock = new MockDirectoryObject("abc", attribs,
                "123456", new Guid().ToString());
            Assert.True(mock.GetLabel(out var label));
            Assert.Equal(Label.Configuration, label);
        }

        [Fact]
        public void Test_GetLabel_CertTemplateObjects() {
            var attribs = new Dictionary<string, object> {
                { LDAPProperties.ObjectClass, new[] { "top", ObjectClass.PKICertificateTemplateClass } },
            };

            var mock = new MockDirectoryObject("abc", attribs,
                "123456", new Guid().ToString());
            Assert.True(mock.GetLabel(out var label));
            Assert.Equal(Label.CertTemplate, label);
        }

        [Fact]
        public void Test_GetLabel_EnterpriseCAObjects() {
            var attribs = new Dictionary<string, object> {
                { LDAPProperties.ObjectClass, new[] { "top", ObjectClass.PKIEnrollmentServiceClass } },
            };

            var mock = new MockDirectoryObject("abc", attribs,
                "123456", new Guid().ToString());
            Assert.True(mock.GetLabel(out var label));
            Assert.Equal(Label.EnterpriseCA, label);
        }

        [Fact]
        public void Test_GetLabel_CertificationAuthorityObjects() {
            var attribs = new Dictionary<string, object> {
                { LDAPProperties.ObjectClass, new[] { "top", ObjectClass.CertificationAuthorityClass } },
            };

            var mock = new MockDirectoryObject($"CN=Test,{DirectoryPaths.RootCALocation.ToUpper()},DC=Testlab,DC=local",
                attribs,
                "123456", new Guid().ToString());
            Assert.True(mock.GetLabel(out var label));
            Assert.Equal(Label.RootCA, label);

            mock.DistinguishedName = $"CN=Test,{DirectoryPaths.AIACALocation.ToUpper()},DC=Testlab,DC=local";
            Assert.True(mock.GetLabel(out label));
            Assert.Equal(Label.AIACA, label);

            mock.DistinguishedName = $"CN=Test,{DirectoryPaths.NTAuthStoreLocation.ToUpper()},DC=Testlab,DC=local";
            Assert.True(mock.GetLabel(out label));
            Assert.Equal(Label.NTAuthStore, label);
        }

        [Theory]
        [InlineData(ObjectClass.SiteClass, Label.Site)]
        [InlineData(ObjectClass.SiteServerClass, Label.SiteServer)]
        [InlineData(ObjectClass.SiteSubnetClass, Label.SiteSubnet)]
        public void Test_GetLabel_SiteObjects(string objectClass, Label expectedLabel) {
            var attribs = new Dictionary<string, object> {
                { LDAPProperties.ObjectClass, new[] { "top", objectClass } },
            };

            var mock = new MockDirectoryObject("CN=Test,CN=Sites,CN=Configuration,DC=Testlab,DC=local",
                attribs,
                "",
                new Guid().ToString());

            Assert.True(mock.GetLabel(out var label));
            Assert.Equal(expectedLabel, label);
        }
        
        [Fact]
        public void Test_GetLabel_NTAuthCertificateObject() {
            var attribs = new Dictionary<string, object> {
                { LDAPProperties.ObjectClass, new[] { "top", ObjectClass.CertificationAuthorityClass } },
            };

            var mock = new MockDirectoryObject($"{DirectoryPaths.NTAuthStoreLocation.ToUpper()},DC=Testlab,DC=local",
                attribs,
                "123456", new Guid().ToString());
            Assert.True(mock.GetLabel(out var label));
            Assert.Equal(Label.NTAuthStore, label);
        }

        [Fact]
        public void Test_GetLabel_NoLabel() {
            var attribs = new Dictionary<string, object> {
                { LDAPProperties.ObjectClass, new[] { "top" } },
            };

            var mock = new MockDirectoryObject($"CN=Test,{DirectoryPaths.RootCALocation.ToUpper()},DC=Testlab,DC=local",
                attribs,
                "123456", new Guid().ToString());
            Assert.False(mock.GetLabel(out var label));
            Assert.Equal(Label.Base, label);

            mock.Properties = new Dictionary<string, object>();
            Assert.False(mock.GetLabel(out label));
            Assert.Equal(Label.Base, label);
        }
    }
}
