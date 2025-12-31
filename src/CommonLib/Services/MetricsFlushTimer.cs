using System;
using System.Threading;

namespace SharpHoundCommonLib.Services;

public class MetricsFlushTimer : IDisposable {
    private readonly Action _flush;
    private readonly Timer _timer;


    public MetricsFlushTimer(
        Action flush,
        TimeSpan interval) {
        _flush = flush;
        _timer = new Timer(
            _ => FlushSafe(),
            null,
            interval,
            interval);
    }

    private void FlushSafe() {
        try {
            _flush();
        } catch {
            // catch all exception and do not kill the process
        }
    }

    public void Dispose() {
        _timer.Dispose();
    }
}