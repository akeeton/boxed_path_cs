using System;
using System.Diagnostics;
using System.IO;
using System.Security;
using Owasp.Untrust.BoxedPaths.Internal;

namespace Owasp.Untrust.BoxedPaths.IO;

/// <summary>
/// Represents a directory, securely wrapping System.IO.DirectoryInfo.
/// Does NOT inherit from DirectoryInfo to prevent path leakage.
/// </summary>
public class BoxedDirectoryInfo : BoxedFileSystemInfo
{
    // Constructor uses the base constructor and a cast to initialize InnerInfo
    public BoxedDirectoryInfo(BoxedPath path)
        // CRITICAL: Call ValidateAndExpose() to construct the internal DirectoryInfo, 
        // then pass both the secure path and the DirectoryInfo to the base constructor.
        : base(path, new DirectoryInfo(path.ValidateAndExpose()))
    {
    }

    internal BoxedDirectoryInfo(DirectoryInfo di, BoxedPath path)
        // CRITICAL: Call ValidateAndExpose() to construct the internal DirectoryInfo, 
        // then pass both the secure path and the DirectoryInfo to the base constructor.
        : base(path, di)
    {
    }

    private static IEnumerable<BoxedFileSystemInfo> BoxFileSystemInfos(
        bool ignoreUnboxed,
        IEnumerable<FileSystemInfo> fileSystemInfos,
        Func<FileSystemInfo, BoxedFileSystemInfo> boxFileSystemInfo
    )
    {
        return fileSystemInfos
            .Select(fileSystemInfo =>
            {
                try
                {
                    return boxFileSystemInfo(fileSystemInfo);
                }
                catch (SecurityException)
                {
                    if (ignoreUnboxed)
                    {
                        return null;
                    }
                    else
                    {
                        throw;
                    }
                }
            })
            .OfType<BoxedFileSystemInfo>(); // Drop nulls
    }

    // Methods specific to directories

    public BoxedFileSystemInfo[] GetFileSystemInfos(bool ignoreUnboxed = false)
    {
        return BoxFileSystemInfos(
                ignoreUnboxed,
                ((DirectoryInfo)InnerInfo).GetFileSystemInfos(),
                fsi =>
                {
                    var boxedPath = new BoxedAbsolute(ThePath.Sandbox, fsi.FullName);
                    return fsi switch
                    {
                        FileInfo => new BoxedFileInfo(boxedPath),
                        DirectoryInfo => new BoxedDirectoryInfo(boxedPath),
                        _ => throw new UnreachableException($"Unexpected FileSystemInfo subtype: {fsi.GetType().Name}"),
                    };
                })
            .ToArray();
    }

    // Secure Operation: Ensures returned file results are wrapped
    public BoxedFileInfo[] GetFiles(bool ignoreUnboxed = false)
    {
        return BoxFileSystemInfos(
                ignoreUnboxed,
                ((DirectoryInfo)InnerInfo).GetFiles(),
                fsi => new BoxedFileInfo(new BoxedAbsolute(ThePath.Sandbox, fsi.FullName)))
            .Cast<BoxedFileInfo>()
            .ToArray();
    }

    // Secure Operation: Ensures returned directory results are wrapped
    public BoxedDirectoryInfo[] GetDirectories(bool ignoreUnboxed = false)
    {
        return BoxFileSystemInfos(
                ignoreUnboxed,
                ((DirectoryInfo)InnerInfo).GetDirectories(),
                fsi => new BoxedDirectoryInfo(new BoxedAbsolute(ThePath.Sandbox, fsi.FullName)))
            .Cast<BoxedDirectoryInfo>()
            .ToArray();
    }

    public void Delete(bool recursive = false)
    {
        ((DirectoryInfo)InnerInfo).Delete(recursive);
    }
}
