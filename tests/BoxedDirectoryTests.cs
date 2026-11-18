using Owasp.Untrust.BoxedPaths.IO;
using System.Security;
using Xunit;

namespace Owasp.Untrust.BoxedPaths.Tests.Functional;

// Note: These tests require the test runner to have permissions to create symlinks (often admin rights on Windows)
public class BoxedDirectoryInfoTests : IDisposable
{
    private readonly DirectoryInfo _testDir;
    private readonly string _outsideRoot;
    private readonly string _sandboxRoot;
    private readonly string _sandboxRootBoxedAndUnboxed;
    private readonly string _sandboxRootBoxedOnly;
    private readonly PathSandbox _sandbox;

    public BoxedDirectoryInfoTests()
    {
        // Creates the following directory tree:
        //
        // Directory.CreateTempSubdirectory()
        // ├── outside_sandbox
        // │   ├── dir
        // │   └── file
        // └── sandbox
        //     ├── boxed_and_unboxed
        //     │   ├── dir
        //     │   ├── file
        //     │   ├── outside_link_dir -> ../../outside_sandbox/dir
        //     │   └── outside_link_file -> ../../outside_sandbox/file
        //     └── boxed_only
        //         ├── dir
        //         ├── file
        //         ├── inside_link_dir -> ../boxed_and_unboxed/dir
        //         └── inside_link_file -> ../boxed_and_unboxed/file

        _testDir = Directory.CreateTempSubdirectory();

        // outside_sandbox/
        _outsideRoot = Path.Join(_testDir.FullName, "outside_sandbox");
        Directory.CreateDirectory(_outsideRoot);
        var outsideRootSubdir = Path.Join(_outsideRoot, "dir");
        Directory.CreateDirectory(outsideRootSubdir);
        var outsideRootSubfile = Path.Join(_outsideRoot, "file");
        File.WriteAllText(outsideRootSubfile, "");

        // sandbox/
        _sandboxRoot = Path.Join(_testDir.FullName, "sandbox");
        Directory.CreateDirectory(_sandboxRoot);

        // sandbox/boxed_and_unboxed/
        _sandboxRootBoxedAndUnboxed = Path.Join(_sandboxRoot, "boxed_and_unboxed");
        Directory.CreateDirectory(_sandboxRootBoxedAndUnboxed);
        var sandboxRootBoxedAndUnboxedSubdir = Path.Join(_sandboxRootBoxedAndUnboxed, "dir");
        Directory.CreateDirectory(sandboxRootBoxedAndUnboxedSubdir);
        var sandboxRootBoxedAndUnboxedSubfile = Path.Join(_sandboxRootBoxedAndUnboxed, "file");
        File.WriteAllText(sandboxRootBoxedAndUnboxedSubfile, "");
        TestHelper.CreateLink(
            Path.Join(_sandboxRootBoxedAndUnboxed, "outside_link_dir"),
            outsideRootSubdir,
            isDirectory: true);
        TestHelper.CreateLink(
            Path.Join(_sandboxRootBoxedAndUnboxed, "outside_link_file"),
            outsideRootSubfile,
            isDirectory: false);

        // sandbox/boxed_only/
        _sandboxRootBoxedOnly = Path.Join(_sandboxRoot, "boxed_only");
        Directory.CreateDirectory(_sandboxRootBoxedOnly);
        Directory.CreateDirectory(Path.Join(_sandboxRootBoxedOnly, "dir"));
        File.WriteAllText(Path.Join(_sandboxRootBoxedOnly, "file"), "");
        TestHelper.CreateLink(
            Path.Join(_sandboxRootBoxedOnly, "inside_link_dir"),
            sandboxRootBoxedAndUnboxedSubdir,
            isDirectory: true);
        TestHelper.CreateLink(
            Path.Join(_sandboxRootBoxedOnly, "inside_link_file"),
            sandboxRootBoxedAndUnboxedSubfile,
            isDirectory: false);

        _sandbox = PathSandbox.BoxRoot(_sandboxRoot);
    }

    // Runs after every test
    public void Dispose()
    {
        TestHelper.Cleanup(_testDir.FullName);
    }

    [Fact]
    public void DirectoryTreeWasCreated()
    {
        // ARRANGE
        var expectedRelativePaths = new List<string>
        {
            "sandbox",
            "outside_sandbox",
            "sandbox/boxed_and_unboxed",
            "sandbox/boxed_only",
            "outside_sandbox/dir",
            "outside_sandbox/file",
            "sandbox/boxed_and_unboxed/dir",
            "sandbox/boxed_and_unboxed/file",
            "sandbox/boxed_and_unboxed/outside_link_dir",
            "sandbox/boxed_and_unboxed/outside_link_file",
            "sandbox/boxed_only/dir",
            "sandbox/boxed_only/file",
            "sandbox/boxed_only/inside_link_dir",
            "sandbox/boxed_only/inside_link_file"
        };

        // ACT
        var actualRelativePaths =
            _testDir
            .GetFileSystemInfos("*", SearchOption.AllDirectories)
            .Select(fsi => Path.GetRelativePath(_testDir.FullName, fsi.FullName));

        // ASSERT
        Assert.Equal(expectedRelativePaths.Order(), actualRelativePaths.Order());
    }

    [Fact]
    public void BoxedDirectoryInfoGetFileSystemInfos_DefaultInDirWithBoxedOnly_ReturnsAllEntriesAndResolvesSymlinks()
    {
        // ARRANGE
        var boxedOnlyDir = new BoxedDirectoryInfo(BoxedPath.Of(_sandbox, _sandboxRootBoxedOnly));
        var expectedRelativePaths = new List<string>
        {
            "boxed_and_unboxed/dir", // Resolved symlink
            "boxed_and_unboxed/file", // Resolved symlink
            "boxed_only/dir",
            "boxed_only/file"
        };

        // ACT
        var actualRelativePaths =
            boxedOnlyDir
            .GetFileSystemInfos()
            .Select(bfsi => Path.GetRelativePath(_sandboxRoot, bfsi.FullPath.ValidateAndExpose()));

        // ASSERT
        Assert.Equal(expectedRelativePaths.Order(), actualRelativePaths.Order());
    }

    [Fact]
    public void BoxedDirectoryInfoGetFileSystemInfos_DefaultInDirWithBoxedAndUnboxed_Throws()
    {
        // ARRANGE
        var boxedAndUnboxedDir = new BoxedDirectoryInfo(BoxedPath.Of(_sandbox, _sandboxRootBoxedAndUnboxed));

        // ACT & ASSERT
        Assert.Throws<SecurityException>(() => boxedAndUnboxedDir.GetFileSystemInfos());
    }

    [Fact]
    public void BoxedDirectoryInfoGetFileSystemInfos_IgnoreUnboxedInDirWithBoxedAndUnboxed_ReturnsBoxedEntries()
    {
        // ARRANGE
        var boxedAndUnboxedDir = new BoxedDirectoryInfo(BoxedPath.Of(_sandbox, _sandboxRootBoxedAndUnboxed));
        var expectedRelativePaths = new List<string>
        {
            "boxed_and_unboxed/dir",
            "boxed_and_unboxed/file"
        };

        // ACT
        var actualRelativePaths =
            boxedAndUnboxedDir
            .GetFileSystemInfos(ignoreUnboxed: true)
            .Select(bfsi => Path.GetRelativePath(_sandboxRoot, bfsi.FullPath.ValidateAndExpose()));

        // ASSERT
        Assert.Equal(expectedRelativePaths.Order(), actualRelativePaths.Order());
    }

    [Fact]
    public void BoxedDirectoryInfoGetFiles_DefaultInDirWithBoxedOnly_ReturnsAllFilesAndResolvesSymlinks()
    {
        // ARRANGE
        var boxedOnlyDir = new BoxedDirectoryInfo(BoxedPath.Of(_sandbox, _sandboxRootBoxedOnly));
        var expectedRelativePaths = new List<string>
        {
            "boxed_and_unboxed/file", // Resolved symlink
            "boxed_only/file"
        };

        // ACT
        var actualRelativePaths =
            boxedOnlyDir
            .GetFiles()
            .Select(bfsi => Path.GetRelativePath(_sandboxRoot, bfsi.FullPath.ValidateAndExpose()));

        // ASSERT
        Assert.Equal(expectedRelativePaths.Order(), actualRelativePaths.Order());
    }

    [Fact]
    public void BoxedDirectoryInfoGetFiles_DefaultInDirWithBoxedAndUnboxed_Throws()
    {
        // ARRANGE
        var boxedAndUnboxedDir = new BoxedDirectoryInfo(BoxedPath.Of(_sandbox, _sandboxRootBoxedAndUnboxed));

        // ACT & ASSERT
        Assert.Throws<SecurityException>(() => boxedAndUnboxedDir.GetFiles());
    }

    [Fact]
    public void BoxedDirectoryInfoGetFiles_IgnoreUnboxedInDirWithBoxedAndUnboxed_ReturnsBoxedFiles()
    {
        // ARRANGE
        var boxedAndUnboxedDir = new BoxedDirectoryInfo(BoxedPath.Of(_sandbox, _sandboxRootBoxedAndUnboxed));
        var expectedRelativePaths = new List<string>
        {
            "boxed_and_unboxed/file"
        };

        // ACT
        var actualRelativePaths =
            boxedAndUnboxedDir
            .GetFiles(ignoreUnboxed: true)
            .Select(bfsi => Path.GetRelativePath(_sandboxRoot, bfsi.FullPath.ValidateAndExpose()));

        // ASSERT
        Assert.Equal(expectedRelativePaths.Order(), actualRelativePaths.Order());
    }

    [Fact]
    public void BoxedDirectoryInfoGetDirectories_DefaultInDirWithBoxedOnly_ReturnsAllDirectoriesAndResolvesSymlinks()
    {
        // ARRANGE
        var boxedOnlyDir = new BoxedDirectoryInfo(BoxedPath.Of(_sandbox, _sandboxRootBoxedOnly));
        var expectedRelativePaths = new List<string>
        {
            "boxed_and_unboxed/dir", // Resolved symlink
            "boxed_only/dir",
        };

        // ACT
        var actualRelativePaths =
            boxedOnlyDir
            .GetDirectories()
            .Select(bfsi => Path.GetRelativePath(_sandboxRoot, bfsi.FullPath.ValidateAndExpose()));

        // ASSERT
        Assert.Equal(expectedRelativePaths.Order(), actualRelativePaths.Order());
    }

    [Fact]
    public void BoxedDirectoryInfoGetDirectories_DefaultInDirWithBoxedAndUnboxed_Throws()
    {
        // ARRANGE
        var boxedAndUnboxedDir = new BoxedDirectoryInfo(BoxedPath.Of(_sandbox, _sandboxRootBoxedAndUnboxed));

        // ACT & ASSERT
        Assert.Throws<SecurityException>(() => boxedAndUnboxedDir.GetDirectories());
    }

    [Fact]
    public void BoxedDirectoryInfoGetDirectories_IgnoreUnboxedInDirWithBoxedAndUnboxed_ReturnsBoxedDirectories()
    {
        // ARRANGE
        var boxedAndUnboxedDir = new BoxedDirectoryInfo(BoxedPath.Of(_sandbox, _sandboxRootBoxedAndUnboxed));
        var expectedRelativePaths = new List<string>
        {
            "boxed_and_unboxed/dir",
        };

        // ACT
        var actualRelativePaths =
            boxedAndUnboxedDir
            .GetDirectories(ignoreUnboxed: true)
            .Select(bfsi => Path.GetRelativePath(_sandboxRoot, bfsi.FullPath.ValidateAndExpose()));

        // ASSERT
        Assert.Equal(expectedRelativePaths.Order(), actualRelativePaths.Order());
    }

    [Fact]
    public void BoxedDirectoryGetFileSystemEntries_DefaultInDirWithBoxedOnly_ReturnsAllEntriesAndResolvesSymlinks()
    {
        // ARRANGE
        var boxedOnlyDirPath = BoxedPath.Of(_sandbox, _sandboxRootBoxedOnly);
        var expectedRelativePaths = new List<string>
        {
            "boxed_and_unboxed/dir", // Resolved symlink
            "boxed_and_unboxed/file", // Resolved symlink
            "boxed_only/dir",
            "boxed_only/file"
        };

        // ACT
        var actualRelativePaths =
            BoxedDirectory.GetFileSystemEntries(boxedOnlyDirPath)
            .Select(bfsi => Path.GetRelativePath(_sandboxRoot, bfsi.FullPath.ValidateAndExpose()));

        // ASSERT
        Assert.Equal(expectedRelativePaths.Order(), actualRelativePaths.Order());
    }

    [Fact]
    public void BoxedDirectoryGetFileSystemEntries_DefaultInDirWithBoxedAndUnboxed_Throws()
    {
        // ARRANGE
        var boxedAndUnboxedDirPath = BoxedPath.Of(_sandbox, _sandboxRootBoxedAndUnboxed);

        // ACT & ASSERT
        Assert.Throws<SecurityException>(() => BoxedDirectory.GetFileSystemEntries(boxedAndUnboxedDirPath));
    }

    [Fact]
    public void BoxedDirectoryGetFileSystemEntries_IgnoreUnboxedInDirWithBoxedAndUnboxed_ReturnsBoxedEntries()
    {
        // ARRANGE
        var boxedAndUnboxedDirPath = BoxedPath.Of(_sandbox, _sandboxRootBoxedAndUnboxed);
        var expectedRelativePaths = new List<string>
        {
            "boxed_and_unboxed/dir",
            "boxed_and_unboxed/file"
        };

        // ACT
        var actualRelativePaths =
            BoxedDirectory.GetFileSystemEntries(boxedAndUnboxedDirPath, ignoreUnboxed: true)
            .Select(bfsi => Path.GetRelativePath(_sandboxRoot, bfsi.FullPath.ValidateAndExpose()));

        // ASSERT
        Assert.Equal(expectedRelativePaths.Order(), actualRelativePaths.Order());
    }

    [Fact]
    public void BoxedDirectoryGetFiles_DefaultInDirWithBoxedOnly_ReturnsAllFilesAndResolvesSymlinks()
    {
        // ARRANGE
        var boxedOnlyDirPath = BoxedPath.Of(_sandbox, _sandboxRootBoxedOnly);
        var expectedRelativePaths = new List<string>
        {
            "boxed_and_unboxed/file", // Resolved symlink
            "boxed_only/file"
        };

        // ACT
        var actualRelativePaths =
            BoxedDirectory.GetFiles(boxedOnlyDirPath)
            .Select(bfsi => Path.GetRelativePath(_sandboxRoot, bfsi.FullPath.ValidateAndExpose()));

        // ASSERT
        Assert.Equal(expectedRelativePaths.Order(), actualRelativePaths.Order());
    }

    [Fact]
    public void BoxedDirectoryGetFiles_DefaultInDirWithBoxedAndUnboxed_Throws()
    {
        // ARRANGE
        var boxedAndUnboxedDirPath = BoxedPath.Of(_sandbox, _sandboxRootBoxedAndUnboxed);

        // ACT & ASSERT
        Assert.Throws<SecurityException>(() => BoxedDirectory.GetFiles(boxedAndUnboxedDirPath));
    }

    [Fact]
    public void BoxedDirectoryGetFiles_IgnoreUnboxedInDirWithBoxedAndUnboxed_ReturnsBoxedFiles()
    {
        // ARRANGE
        var boxedAndUnboxedDirPath = BoxedPath.Of(_sandbox, _sandboxRootBoxedAndUnboxed);
        var expectedRelativePaths = new List<string>
        {
            "boxed_and_unboxed/file"
        };

        // ACT
        var actualRelativePaths =
            BoxedDirectory.GetFiles(boxedAndUnboxedDirPath, ignoreUnboxed: true)
            .Select(bfsi => Path.GetRelativePath(_sandboxRoot, bfsi.FullPath.ValidateAndExpose()));

        // ASSERT
        Assert.Equal(expectedRelativePaths.Order(), actualRelativePaths.Order());
    }

    [Fact]
    public void BoxedDirectoryGetDirectories_DefaultInDirWithBoxedOnly_ReturnsAllDirectoriesAndResolvesSymlinks()
    {
        // ARRANGE
        var boxedOnlyDirPath = BoxedPath.Of(_sandbox, _sandboxRootBoxedOnly);
        var expectedRelativePaths = new List<string>
        {
            "boxed_and_unboxed/dir", // Resolved symlink
            "boxed_only/dir",
        };

        // ACT
        var actualRelativePaths =
            BoxedDirectory.GetDirectories(boxedOnlyDirPath)
            .Select(bfsi => Path.GetRelativePath(_sandboxRoot, bfsi.FullPath.ValidateAndExpose()));

        // ASSERT
        Assert.Equal(expectedRelativePaths.Order(), actualRelativePaths.Order());
    }

    [Fact]
    public void BoxedDirectoryGetDirectories_DefaultInDirWithBoxedAndUnboxed_Throws()
    {
        // ARRANGE
        var boxedAndUnboxedDirPath = BoxedPath.Of(_sandbox, _sandboxRootBoxedAndUnboxed);

        // ACT & ASSERT
        Assert.Throws<SecurityException>(() => BoxedDirectory.GetDirectories(boxedAndUnboxedDirPath));
    }

    [Fact]
    public void BoxedDirectoryGetDirectories_IgnoreUnboxedInDirWithBoxedAndUnboxed_ReturnsBoxedDirectories()
    {
        // ARRANGE
        var boxedAndUnboxedDirPath = BoxedPath.Of(_sandbox, _sandboxRootBoxedAndUnboxed);
        var expectedRelativePaths = new List<string>
        {
            "boxed_and_unboxed/dir",
        };

        // ACT
        var actualRelativePaths =
            BoxedDirectory.GetDirectories(boxedAndUnboxedDirPath, ignoreUnboxed: true)
            .Select(bfsi => Path.GetRelativePath(_sandboxRoot, bfsi.FullPath.ValidateAndExpose()));

        // ASSERT
        Assert.Equal(expectedRelativePaths.Order(), actualRelativePaths.Order());
    }
}