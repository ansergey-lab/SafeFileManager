namespace SafeFileManager;

public static class SafePathPolicy
{
    public static string Resolve(string root, string relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath) ||
            Path.IsPathRooted(relativePath))
        {
            throw new ArgumentException(
                "Нужно указать относительный путь внутри Files.");
        }

        string fullRoot = Path.GetFullPath(root);

        string fullPath = Path.GetFullPath(
            Path.Combine(fullRoot, relativePath));

        string rootPrefix = fullRoot.TrimEnd(
            Path.DirectorySeparatorChar)
            + Path.DirectorySeparatorChar;

        if (!fullPath.StartsWith(
                rootPrefix,
                OperatingSystem.IsWindows()
                    ? StringComparison.OrdinalIgnoreCase
                    : StringComparison.Ordinal))
        {
            throw new UnauthorizedAccessException(
                "Выход за пределы рабочей папки запрещён.");
        }

        return fullPath;
    }
}