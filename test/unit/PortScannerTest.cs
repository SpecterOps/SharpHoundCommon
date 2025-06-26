using System;
using System.Diagnostics.CodeAnalysis;
using SharpHoundCommonLib.Processors;
using Xunit;

namespace CommonLibTest;

[SuppressMessage("Interoperability", "CA1416:Validate platform compatibility")]
public class PortScannerTest {
    [Fact]
    public async Task PortScanner_CheckPort_TimeoutException() {
        var hostname = "192.168.254.254"; // Use a non-routable IP to ensure timeout
        var port = 445;
        var scanner = new PortScanner();
        var ex = await Assert.ThrowsAsync<TimeoutException>(() => scanner.CheckPort(hostname, port, 100, true));
        Assert.Equal("Timed Out", ex.Message);
    }
}