namespace SharpHoundCommonLib.Interfaces;

public interface ILabelValuesCache {
    string[] Intern(string[] values);
}