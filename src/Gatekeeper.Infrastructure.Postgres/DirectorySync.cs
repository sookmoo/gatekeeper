using System.Runtime.InteropServices;

namespace Gatekeeper.Infrastructure.Postgres;

/// <summary>fsync of a directory, so a newly created file's directory entry survives a crash. .NET cannot open a directory handle on Linux, hence libc.</summary>
public static class DirectorySync
{
    [DllImport("libc", EntryPoint = "open", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern int Open(string path, int flags);

    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static extern int Fsync(int fd);

    [DllImport("libc", EntryPoint = "close")]
    private static extern int Close(int fd);

    /// <summary>True when the directory was synced. False elsewhere than Linux or on any error (best effort, never throws).</summary>
    public static bool Sync(string? directory)
    {
        if (directory is null || !OperatingSystem.IsLinux()) return false;
        try
        {
            var fd = Open(directory, 0); // O_RDONLY: a directory can be opened read-only and fsynced
            if (fd < 0) return false;
            try { return Fsync(fd) == 0; }
            finally { Close(fd); }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or MarshalDirectiveException) { return false; }
    }
}
