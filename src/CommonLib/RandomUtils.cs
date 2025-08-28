using System;
using System.Threading;

namespace SharpHoundCommonLib;

public static class RandomUtils {
    private static readonly ThreadLocal<Random> Random = new(() => new Random());
    
    public static double NextDouble() => Random.Value.NextDouble();
    public static double Between(double minValue, double maxValue) => Random.Value.NextDouble() * (maxValue - minValue) + minValue;
}