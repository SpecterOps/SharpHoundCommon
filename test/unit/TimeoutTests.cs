using System;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace CommonLibTest;

// [CollectionDefinition("NonParallelCollection", DisableParallelization = true)]
// [Collection("NonParallelCollection")]
public class TimeoutTests {
    [Fact]
    public async Task ExecuteWithTimeout_Success() {
        var timeout = TimeSpan.FromSeconds(1);
        var func = (CancellationToken t) => {
            Thread.Sleep(TimeSpan.FromMilliseconds(100));
        };
        var result = await SharpHoundCommonLib.Timeout.ExecuteWithTimeout(timeout, func);
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public async Task ExecuteWithTimeout_Timeout() {
        var timeout = TimeSpan.FromMilliseconds(100);
        var func = (CancellationToken t) => {
            Thread.Sleep(TimeSpan.FromSeconds(1));
        };
        var result = await SharpHoundCommonLib.Timeout.ExecuteWithTimeout(timeout, func);
        Assert.False(result.IsSuccess);
        Assert.StartsWith("Timeout", result.Error);
    }

    [Fact]
    public async Task ExecuteWithTimeout_Timeout_Cancel() {
        var shouldRemainFalse = false;
        var timeout = TimeSpan.FromMilliseconds(100);
        var func = (CancellationToken t) => {
            Thread.Sleep(TimeSpan.FromMilliseconds(500));
            t.ThrowIfCancellationRequested();
            shouldRemainFalse = true;
        };
        var result = await SharpHoundCommonLib.Timeout.ExecuteWithTimeout(timeout, func);
        await Task.Delay(TimeSpan.FromMilliseconds(600));
        Assert.False(shouldRemainFalse, $"{nameof(SharpHoundCommonLib.Timeout.ExecuteWithTimeout)} did not pass a cancelled token following timeout. Function {nameof(func)} did not exit early.");
    }

    [Fact]
    public async Task ExecuteWithTimeout_RaisesException() {
        var timeout = TimeSpan.FromSeconds(1);
        var func = (CancellationToken t) => {
            throw new ApplicationException("I am an exception");
        };
        await Assert.ThrowsAsync<ApplicationException>(() => SharpHoundCommonLib.Timeout.ExecuteWithTimeout(timeout, func));
    }

    [Fact]
    public async Task ExecuteWithTimeout_ParentTokenCancel() {
        var cancelledToken = new CancellationToken(true);
        var timeout = TimeSpan.FromSeconds(1);
        var func = (CancellationToken t) => {
            Thread.Sleep(TimeSpan.FromMilliseconds(100));
        };
        var result = await SharpHoundCommonLib.Timeout.ExecuteWithTimeout(timeout, func, cancelledToken);
        Assert.False(result.IsSuccess);
        Assert.Equal("Cancellation requested", result.Error);
    }

    [Fact]
    public async Task ExecuteWithTimeout_T_Success() {
        var timeout = TimeSpan.FromSeconds(1);
        var func = (CancellationToken t) => {
            Thread.Sleep(TimeSpan.FromMilliseconds(100));
            return true;
        };
        var result = await SharpHoundCommonLib.Timeout.ExecuteWithTimeout(timeout, func);
        Assert.True(result.IsSuccess);
        Assert.True(result.Value);
    }

    [Fact]
    public async Task ExecuteWithTimeout_T_Timeout() {
        var timeout = TimeSpan.FromMilliseconds(100);
        var func = (CancellationToken t) => {
            Thread.Sleep(TimeSpan.FromSeconds(1));
            return true;
        };
        var result = await SharpHoundCommonLib.Timeout.ExecuteWithTimeout(timeout, func);
        Assert.False(result.IsSuccess);
        Assert.StartsWith("Timeout", result.Error);
    }

    [Fact]
    public async Task ExecuteWithTimeout_T_Timeout_Cancel() {
        var shouldRemainFalse = false;
        var timeout = TimeSpan.FromMilliseconds(100);
        var func = (CancellationToken t) => {
            Thread.Sleep(TimeSpan.FromMilliseconds(500));
            t.ThrowIfCancellationRequested();
            shouldRemainFalse = true;
            return true;
        };
        var result = await SharpHoundCommonLib.Timeout.ExecuteWithTimeout(timeout, func);
        await Task.Delay(TimeSpan.FromMilliseconds(600));
        Assert.False(shouldRemainFalse, $"{nameof(SharpHoundCommonLib.Timeout.ExecuteWithTimeout)} did not pass a cancelled token following timeout. Function {nameof(func)} did not exit early.");
    }

    [Fact]
    public async Task ExecuteWithTimeout_T_RaisesException() {
        var timeout = TimeSpan.FromSeconds(1);
        var func = (CancellationToken t) => {
            throw new ApplicationException("I am an exception");
#pragma warning disable CS0162 // Unreachable code detected
            // Function should be type Func<CancellationToken, bool>
            return true;
#pragma warning restore CS0162 // Unreachable code detected
        };
        await Assert.ThrowsAsync<ApplicationException>(() => SharpHoundCommonLib.Timeout.ExecuteWithTimeout(timeout, func));
    }

    [Fact]
    public async Task ExecuteWithTimeout_T_ParentTokenCancel() {
        var cancelledToken = new CancellationToken(true);
        var timeout = TimeSpan.FromSeconds(1);
        var func = (CancellationToken t) => {
            Thread.Sleep(TimeSpan.FromMilliseconds(100));
            return true;
        };
        var result = await SharpHoundCommonLib.Timeout.ExecuteWithTimeout(timeout, func, cancelledToken);
        Assert.False(result.IsSuccess);
        Assert.Equal("Cancellation requested", result.Error);
    }

    [Fact]
    public async Task ExecuteWithTimeout_Task_Success() {
        var timeout = TimeSpan.FromSeconds(1);
        var func = async (CancellationToken t) => {
            await Task.Delay(TimeSpan.FromMilliseconds(100));
        };
        var result = await SharpHoundCommonLib.Timeout.ExecuteWithTimeout(timeout, func);
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public async Task ExecuteWithTimeout_Task_Timeout() {
        var timeout = TimeSpan.FromMilliseconds(100);
        var func = async (CancellationToken t) => {
            await Task.Delay(TimeSpan.FromSeconds(1));
        };
        var result = await SharpHoundCommonLib.Timeout.ExecuteWithTimeout(timeout, func);
        Assert.False(result.IsSuccess);
        Assert.StartsWith("Timeout", result.Error);
    }

    [Fact]
    public async Task ExecuteWithTimeout_Task_Timeout_Cancel() {
        var shouldRemainFalse = false;
        var timeout = TimeSpan.FromMilliseconds(100);
        var func = async (CancellationToken t) => {
            await Task.Delay(TimeSpan.FromMilliseconds(500));
            t.ThrowIfCancellationRequested();
            shouldRemainFalse = true;
        };
        var result = await SharpHoundCommonLib.Timeout.ExecuteWithTimeout(timeout, func);
        await Task.Delay(TimeSpan.FromMilliseconds(600));
        Assert.False(shouldRemainFalse, $"{nameof(SharpHoundCommonLib.Timeout.ExecuteWithTimeout)} did not pass a cancelled token following timeout. Function {nameof(func)} did not exit early.");
    }

    [Fact]
    public async Task ExecuteWithTimeout_Task_RaisesException() {
        var timeout = TimeSpan.FromSeconds(1);
        var func = async (CancellationToken t) => {
            await Task.Delay(TimeSpan.FromMilliseconds(10));
            throw new ApplicationException("I am an exception");
        };
        await Assert.ThrowsAsync<ApplicationException>(() => SharpHoundCommonLib.Timeout.ExecuteWithTimeout(timeout, func));
    }

    [Fact]
    public async Task ExecuteWithTimeout_Task_ParentTokenCancel() {
        var cancelledToken = new CancellationToken(true);
        var timeout = TimeSpan.FromSeconds(1);
        var func = async (CancellationToken t) => {
            await Task.Delay(TimeSpan.FromMilliseconds(100));
        };
        var result = await SharpHoundCommonLib.Timeout.ExecuteWithTimeout(timeout, func, cancelledToken);
        Assert.False(result.IsSuccess);
        Assert.Equal("Cancellation requested", result.Error);
    }

    [Fact]
    public async Task ExecuteWithTimeout_Task_T_Success() {
        var timeout = TimeSpan.FromSeconds(1);
        var func = async (CancellationToken t) => {
            await Task.Delay(TimeSpan.FromMilliseconds(100));
            return true;
        };
        var result = await SharpHoundCommonLib.Timeout.ExecuteWithTimeout(timeout, func);
        Assert.True(result.IsSuccess);
        Assert.True(result.Value);
    }

    [Fact]
    public async Task ExecuteWithTimeout_Task_T_Timeout() {
        var timeout = TimeSpan.FromMilliseconds(100);
        var func = async (CancellationToken t) => {
            await Task.Delay(TimeSpan.FromSeconds(1));
            return true;
        };
        var result = await SharpHoundCommonLib.Timeout.ExecuteWithTimeout(timeout, func);
        Assert.False(result.IsSuccess);
        Assert.StartsWith("Timeout", result.Error);
    }

    [Fact]
    public async Task ExecuteWithTimeout_Task_T_Timeout_Cancel() {
        var shouldRemainFalse = false;
        var timeout = TimeSpan.FromMilliseconds(100);
        var func = async (CancellationToken t) => {
            await Task.Delay(TimeSpan.FromMilliseconds(500));
            t.ThrowIfCancellationRequested();
            shouldRemainFalse = true;
            return true;
        };
        var result = await SharpHoundCommonLib.Timeout.ExecuteWithTimeout(timeout, func);
        await Task.Delay(TimeSpan.FromMilliseconds(600));
        Assert.False(shouldRemainFalse, $"{nameof(SharpHoundCommonLib.Timeout.ExecuteWithTimeout)} did not pass a cancelled token following timeout. Function {nameof(func)} did not exit early.");
    }

    [Fact]
    public async Task ExecuteWithTimeout_Task_T_RaisesException() {
        var timeout = TimeSpan.FromSeconds(1);
        var func = async (CancellationToken t) => {
            await Task.Delay(TimeSpan.FromMilliseconds(10));
            throw new ApplicationException("I am an exception");
#pragma warning disable CS0162 // Unreachable code detected
            // Function should be type Func<CancellationToken, Task<bool>>
            return true;
#pragma warning restore CS0162 // Unreachable code detected
        };
        await Assert.ThrowsAsync<ApplicationException>(() => SharpHoundCommonLib.Timeout.ExecuteWithTimeout(timeout, func));
    }

    [Fact]
    public async Task ExecuteWithTimeout_Task_T_ParentTokenCancel() {
        var cancelledToken = new CancellationToken(true);
        var timeout = TimeSpan.FromSeconds(1);
        var func = async (CancellationToken t) => {
            await Task.Delay(TimeSpan.FromMilliseconds(100));
            return true;
        };
        var result = await SharpHoundCommonLib.Timeout.ExecuteWithTimeout(timeout, func, cancelledToken);
        Assert.False(result.IsSuccess);
        Assert.Equal("Cancellation requested", result.Error);
    }
}