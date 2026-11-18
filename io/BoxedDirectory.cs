using System;
using System.IO;
using System.Security;
using Owasp.Untrust.BoxedPaths.Internal;

namespace Owasp.Untrust.BoxedPaths.IO;

public static class BoxedDirectory
{
    // All methods now use the validated path from GetUnsecuredPath
    public static bool Exists(BoxedPath path) => Directory.Exists(path.ValidateAndExpose());
    public static BoxedDirectoryInfo CreateDirectory(BoxedPath path)
    {
       DirectoryInfo di = Directory.CreateDirectory(path.ValidateAndExpose());
       return new BoxedDirectoryInfo(di, path);
    }

    public static void Delete(BoxedPath path, bool recursive = false) => Directory.Delete(path.ValidateAndExpose(), recursive);

    private static BoxedAbsolute[] BoxFileSystemEntries(
        bool ignoreUnboxed,
        BoxedPath path,
        Func<string, string[]> getFileSystemEntries
    )
    {
        return
            getFileSystemEntries(path.ValidateAndExpose())
            .Select(fileSystemEntry =>
            {
                try
                {
                    return new BoxedAbsolute(path.Sandbox, fileSystemEntry);
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
            .OfType<BoxedAbsolute>() // Drop nulls
            .ToArray();
    }

    public static BoxedPath[] GetFileSystemEntries(BoxedPath path, bool ignoreUnboxed = false)
    {
        return BoxFileSystemEntries(ignoreUnboxed, path, Directory.GetFileSystemEntries);
    }

    public static BoxedPath[] GetFiles(BoxedPath path, bool ignoreUnboxed = false)
    {
        return BoxFileSystemEntries(ignoreUnboxed, path, Directory.GetFiles);
    }

    public static BoxedPath[] GetDirectories(BoxedPath path, bool ignoreUnboxed = false)
    {
        return BoxFileSystemEntries(ignoreUnboxed, path, Directory.GetDirectories);
    }
}
