using System;
using System.Diagnostics.CodeAnalysis;
using SharpHoundCommonLib.Processors;
using Xunit;

namespace CommonLibTest;

[SuppressMessage("Interoperability", "CA1416:Validate platform compatibility")]
public class PortScannerTest {
    [Fact]
    public void PortScanner_CheckPort_TimeoutException() {
        var hostname = "primary.testlab.local";
        var port = 445;
        var scanner = new PortScanner();
        var ex = Assert.ThrowsAsync<TimeoutException>(() => scanner.CheckPort(hostname, port, 1, true));
        Assert.Equal("Timed Out", ex.Result.Message);
    }
}