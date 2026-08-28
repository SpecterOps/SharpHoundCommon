using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using SharpHoundCommonLib.Processors;
using Xunit;

namespace CommonLibTest;

[SuppressMessage("Interoperability", "CA1416:Validate platform compatibility")]
public class PortScannerTest {
    [Fact]
    public async Task PortScannerContext_ScannersShareCache() {
        using var context = new PortScannerContext();
        var firstScanner = context.CreatePortScanner();
        var secondScanner = context.CreatePortScanner();

        // An invalid port is cached as false. A cache miss with throwError enabled would throw,
        // so returning false demonstrates that the second scanner used the first scanner's result.
        Assert.False(await firstScanner.CheckPort("localhost", -1));
        Assert.False(await secondScanner.CheckPort("localhost", -1, throwError: true));
    }

    [Fact]
    public async Task PortScannerContext_ScannersDoNotShareCacheAcrossContexts() {
        using var firstContext = new PortScannerContext();
        using var secondContext = new PortScannerContext();

        Assert.False(await firstContext.CreatePortScanner().CheckPort("localhost", -1));
        // The second context has no cached result and therefore attempts the invalid scan.
        await Assert.ThrowsAnyAsync<Exception>(() =>
            secondContext.CreatePortScanner().CheckPort("localhost", -1, throwError: true));
    }

    [Fact]
    public void PortScannerContext_CreateScanner_AfterDispose_Throws() {
        var context = new PortScannerContext();
        context.Dispose();

        Assert.Throws<ObjectDisposedException>(() => context.CreatePortScanner());
    }

    [Fact]
    public async Task PortScannerContext_Scanner_AfterDispose_Throws() {
        var context = new PortScannerContext();
        var scanner = context.CreatePortScanner();
        context.Dispose();

        await Assert.ThrowsAsync<ObjectDisposedException>(() => scanner.CheckPort("localhost"));
    }

    //// Throws "no such host is known" exception
    // [Fact]
    // public void PortScanner_CheckPort_TimeoutException() {
    //     var hostname = "primary.testlab.local";
    //     var port = 445;
    //     var scanner = new PortScanner();
    //     var ex = Assert.ThrowsAsync<TimeoutException>(() => scanner.CheckPort(hostname, port, 1, true));
    //     Assert.Equal("Timed Out", ex.Result.Message);
    // }
}
