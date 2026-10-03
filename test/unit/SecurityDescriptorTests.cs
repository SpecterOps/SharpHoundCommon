using System.DirectoryServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using SharpHoundCommonLib;
using Xunit;

namespace CommonLibTest;

public class SecurityDescriptorTests
{
    [SupportedOSPlatform("windows")]
    [WindowsOnlyFact]
    public void GetOwner_SecurityDescriptorWithoutOwner_ReturnsNull()
    {
        var descriptor = new ActiveDirectorySecurityDescriptor(new ActiveDirectorySecurity());

        var owner = descriptor.GetOwner(typeof(SecurityIdentifier));

        Assert.Null(owner);
    }
}
