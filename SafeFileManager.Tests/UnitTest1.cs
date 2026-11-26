using SafeFileManager;

namespace SafeFileManager.Tests;

public class SafePathPolicyTests
{
    [Fact]
    public void Resolve_ValidRelativePath_ReturnsPathInsideRoot()
    {
        string root = Path.Combine(Path.GetTempPath(), "SafeFileManagerTests");

        string result = SafePathPolicy.Resolve(root, "Documents/note.txt");

        string expected = Path.GetFullPath(
            Path.Combine(root, "Documents", "note.txt"));

        Assert.Equal(expected, result);
    }

    [Fact]
    public void Resolve_PathTraversal_ThrowsUnauthorizedAccessException()
    {
        string root = Path.Combine(Path.GetTempPath(), "SafeFileManagerTests");

        Assert.Throws<UnauthorizedAccessException>(
            () => SafePathPolicy.Resolve(root, "../outside.txt"));
    }

    [Fact]
    public void Resolve_AbsolutePath_ThrowsArgumentException()
    {
        string root = Path.Combine(Path.GetTempPath(), "SafeFileManagerTests");
        string absolutePath = Path.GetFullPath(
            Path.Combine(root, "outside.txt"));

        Assert.Throws<ArgumentException>(
            () => SafePathPolicy.Resolve(root, absolutePath));
    }

    [Fact]
    public void Resolve_EmptyPath_ThrowsArgumentException()
    {
        string root = Path.Combine(Path.GetTempPath(), "SafeFileManagerTests");

        Assert.Throws<ArgumentException>(
            () => SafePathPolicy.Resolve(root, ""));
    }
}