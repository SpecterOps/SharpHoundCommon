using System;
using CommonLibTest.Facades;
using Microsoft.Extensions.Logging;
using Moq;
using SharpHoundCommonLib;
using Xunit;

namespace CommonLibTest;

public class LdapConfigTests {
    [Fact]
    public void UserDomain_IsNullByDefault() {
        Assert.Null(new LdapConfig().UserDomain);
    }

    [Theory]
    [InlineData("child.example.test")]
    [InlineData("CHILD")]
    public void SetLdapConfig_LogsUserDomain(string userDomain) {
        var logger = new Mock<ILogger<LdapUtils>>();
        var utils = new LdapUtils(log: logger.Object);
        var config = new LdapConfig { UserDomain = userDomain };

        utils.SetLdapConfig(config);

        logger.VerifyLogContains(LogLevel.Information, "New LDAP Config Set:", $"UserDomain: {userDomain}");
        Assert.Contains($"UserDomain: {userDomain}{Environment.NewLine}", config.ToString());
    }

    [Fact]
    public void AllowUncontrolledDomainFallback_IsDisabledByDefault() {
        Assert.False(new LdapConfig().AllowUncontrolledDomainFallback);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SetLdapConfig_LogsAllowUncontrolledDomainFallback(bool enabled) {
        var logger = new Mock<ILogger<LdapUtils>>();
        var utils = new LdapUtils(log: logger.Object);
        var config = new LdapConfig { AllowUncontrolledDomainFallback = enabled };

        utils.SetLdapConfig(config);

        logger.VerifyLogContains(LogLevel.Information,
            "New LDAP Config Set:", $"AllowUncontrolledDomainFallback: {enabled}");
        Assert.Contains($"AllowUncontrolledDomainFallback: {enabled}{Environment.NewLine}", config.ToString());
    }
}
