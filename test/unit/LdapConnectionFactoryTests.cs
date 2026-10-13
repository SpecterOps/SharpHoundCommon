using System;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Reflection;
using SharpHoundCommonLib;
using Xunit;

namespace CommonLibTest;

public class LdapConnectionFactoryTests {
    // Credential is write-only; inspect its stored value without binding to a server.
    private static NetworkCredential GetCredential(LdapConnection connection) {
        var field = typeof(DirectoryConnection).GetFields(BindingFlags.Instance | BindingFlags.NonPublic)
            .Single(x => x.FieldType == typeof(NetworkCredential));
        return (NetworkCredential)field.GetValue(connection);
    }

    [Theory]
    [InlineData(false, false, 0, 0, 389)]
    [InlineData(true, false, 0, 0, 636)]
    [InlineData(false, false, 1389, 1636, 1389)]
    [InlineData(true, false, 1389, 1636, 1636)]
    [InlineData(false, true, 1389, 1636, 3268)]
    [InlineData(true, true, 1389, 1636, 3269)]
    public void Create_UsesConfiguredPortsAndSessionOptions(bool ssl, bool globalCatalog,
        int port, int sslPort, int expectedPort) {
        var config = new LdapConfig { Port = port, SSLPort = sslPort };

        using var connection = LdapConnectionFactory.Create(config, "dc.example.test", ssl, globalCatalog);

        var identifier = Assert.IsType<LdapDirectoryIdentifier>(connection.Directory);
        Assert.Equal(new[] { "dc.example.test" }, identifier.Servers);
        Assert.Equal(expectedPort, identifier.PortNumber);
        Assert.False(identifier.FullyQualifiedDnsHostName);
        Assert.False(identifier.Connectionless);
        Assert.Equal(TimeSpan.FromMinutes(5), connection.Timeout);
        Assert.Equal(3, connection.SessionOptions.ProtocolVersion);
        Assert.Equal(ReferralChasingOptions.None, connection.SessionOptions.ReferralChasing);
        // On Windows this getter reports connection SSL status; an unbound connection
        // does not report an established SSL session. Compare with a configured baseline.
        using var baseline = new LdapConnection(new LdapDirectoryIdentifier("dc.example.test", expectedPort, false, false));
        baseline.SessionOptions.SecureSocketLayer = ssl;
        Assert.Equal(baseline.SessionOptions.SecureSocketLayer, connection.SessionOptions.SecureSocketLayer);
    }

    [Theory]
    [InlineData(false, false, true)]
    [InlineData(false, true, false)]
    [InlineData(true, false, false)]
    [InlineData(true, true, false)]
    public void Create_PreservesSigningAndSealing(bool ssl, bool disableSigning, bool expected) {
        var config = new LdapConfig { DisableSigning = disableSigning };

        using var connection = LdapConnectionFactory.Create(config, "dc.example.test", ssl);

        Assert.Equal(expected, connection.SessionOptions.Signing);
        Assert.Equal(expected, connection.SessionOptions.Sealing);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Create_OnlyBypassesCertificateVerificationWhenConfigured(bool disableVerification) {
        var config = new LdapConfig { DisableCertVerification = disableVerification };

        using var connection = LdapConnectionFactory.Create(config, "dc.example.test", true);

        var callback = connection.SessionOptions.VerifyServerCertificate;
        if (disableVerification) {
            Assert.NotNull(callback);
            Assert.True(callback(connection, null));
        }
        else {
            Assert.Null(callback);
        }
    }

    [Theory]
    [InlineData(AuthType.Kerberos)]
    [InlineData(AuthType.Negotiate)]
    [InlineData(AuthType.Basic)]
    public void Create_UsesConfiguredAuthenticationType(AuthType authType) {
        var config = new LdapConfig { AuthType = authType };

        using var connection = LdapConnectionFactory.Create(config, "dc.example.test", true);

        Assert.Equal(authType, connection.AuthType);
    }

    [Fact]
    public void Create_LeavesCredentialsUnsetWithoutUsername() {
        var config = new LdapConfig { Password = "unused-test-password", UserDomain = "child.example.test" };

        using var connection = LdapConnectionFactory.Create(config, "dc.example.test", true);

        Assert.Null(GetCredential(connection));
    }

    [Theory]
    [InlineData("test-user", "test-password")]
    [InlineData("test-user", null)]
    [InlineData("", "test-password")]
    public void Create_PreservesExplicitCredentials(string username, string password) {
        var config = new LdapConfig { Username = username, Password = password, UserDomain = "OTHER" };

        using var connection = LdapConnectionFactory.Create(config, "dc.example.test", true);

        var credential = GetCredential(connection);
        Assert.NotNull(credential);
        Assert.Equal(username, credential.UserName);
        Assert.Equal(password ?? "", credential.Password);
        Assert.Equal("", credential.Domain);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Create_PinnedServerUsesExplicitHostAndDisablesReconnectAndReferrals(bool ssl) {
        var config = new LdapConfig { Server = "dc.example.test", Port = 1389, SSLPort = 1636 };

        using var connection = LdapConnectionFactory.Create(config, config.Server, ssl, pinServer: true);

        var identifier = Assert.IsType<LdapDirectoryIdentifier>(connection.Directory);
        Assert.Equal(new[] { config.Server }, identifier.Servers);
        Assert.Equal(ssl ? 1636 : 1389, identifier.PortNumber);
        Assert.True(identifier.FullyQualifiedDnsHostName);
        Assert.False(identifier.Connectionless);
        Assert.False(connection.SessionOptions.AutoReconnect);
        Assert.Equal(ReferralChasingOptions.None, connection.SessionOptions.ReferralChasing);
    }

    [Fact]
    public void Create_UnpinnedConnectionPreservesDefaultReconnectBehaviorEvenWithConfiguredServer() {
        var config = new LdapConfig { Server = "dc.example.test" };
        using var original = new LdapConnection(new LdapDirectoryIdentifier(config.Server, 636, false, false));

        using var connection = LdapConnectionFactory.Create(config, config.Server, true);

        Assert.Equal(original.SessionOptions.AutoReconnect, connection.SessionOptions.AutoReconnect);
        Assert.False(((LdapDirectoryIdentifier)connection.Directory).FullyQualifiedDnsHostName);
    }
}
