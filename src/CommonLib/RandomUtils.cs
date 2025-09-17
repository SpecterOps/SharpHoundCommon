using System;
using System.Threading;

namespace SharpHoundCommonLib;

public static class RandomUtils {
    private static readonly ThreadLocal<Random> Random = new(() => new Random());
    
    public static double NextDouble() => Random.Value.NextDouble();
    public static long NextLong() => LongRandom(long.MinValue, long.MaxValue);
    private static long LongRandom(long min, long max) {
        var buf = new byte[8];
        Random.Value.NextBytes(buf);
        var longRand = BitConverter.ToInt64(buf, 0);
        return (Math.Abs(longRand % (max - min)) + min);
    }
    public static double Between(double minValue, double maxValue) => Random.Value.NextDouble() * (maxValue - minValue) + minValue;
    public static long Between(long minValue, long maxValue) => LongRandom(minValue, maxValue);
}