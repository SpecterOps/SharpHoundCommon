using System;

namespace SharpHoundCommonLib.Models;

public sealed class FileMetricSinkOptions {
    public TimeSpan FlushInterval { get; set; } = TimeSpan.FromSeconds(10);
    public string TimestampFormat { get; set; } = "yyyy-MM-dd HH:mm:ss.fff";
    public bool FlushWriter { get; set; } = true;
}