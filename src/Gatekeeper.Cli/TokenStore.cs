using System.Text.Json;

namespace Gatekeeper.Cli;

/// <summary>A saved login. The tokens are only ever sent to <see cref="Origin"/>.</summary>
public sealed record StoredToken(
    string Origin, string AccessToken, DateTimeOffset ExpiresAt, string Username,
    string? RefreshToken = null, DateTimeOffset? RefreshExpiresAt = null);

public interface ITokenStore
{
    StoredToken? Load();
    void Save(StoredToken token);
    void Clear();

    /// <summary>
    /// Held while refreshing: refresh tokens rotate, so two commands refreshing at once would present the same token twice,
    /// which the server treats as theft and answers by ending the session.
    /// </summary>
    IDisposable RefreshLock();
}

/// <summary>Keeps the token in $XDG_STATE_HOME/gatekeeper/token.json (mode 0600, directory 0700).</summary>
public sealed class FileTokenStore(string? path = null) : ITokenStore
{
    private readonly string _path = path ?? DefaultPath();

    public static string DefaultPath()
    {
        var state = Environment.GetEnvironmentVariable("XDG_STATE_HOME");
        if (string.IsNullOrWhiteSpace(state))
            state = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "state");
        return Path.Combine(state, "gatekeeper", "token.json");
    }

    public StoredToken? Load()
    {
        try
        {
            return JsonSerializer.Deserialize<StoredToken>(File.ReadAllText(_path));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return null; // missing or unreadable means "not logged in"
        }
    }

    public void Save(StoredToken token)
    {
        var dir = Path.GetDirectoryName(_path)!;
        if (!OperatingSystem.IsWindows()) Directory.CreateDirectory(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        else Directory.CreateDirectory(dir);
        // Write to a private temp file first, then move it over: the token is never visible with loose permissions.
        var temp = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        using (var stream = new FileStream(temp, options))
            JsonSerializer.Serialize(stream, token);
        File.Move(temp, _path, overwrite: true);
    }

    public IDisposable RefreshLock()
    {
        var dir = Path.GetDirectoryName(_path)!;
        if (!OperatingSystem.IsWindows()) Directory.CreateDirectory(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        else Directory.CreateDirectory(dir);
        var options = new FileStreamOptions { Mode = FileMode.OpenOrCreate, Access = FileAccess.ReadWrite, Share = FileShare.None };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (true)
        {
            try
            {
                return new FileStream(_path + ".lock", options); // exclusive open = the lock; disposing releases it
            }
            catch (IOException) when (DateTime.UtcNow < deadline)
            {
                Thread.Sleep(50);
            }
        }
    }

    public void Clear()
    {
        try
        {
            File.Delete(_path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new CliException(1, $"Could not remove the saved login at {_path}: {ex.Message}");
        }
    }
}

/// <summary>In-memory store for tests.</summary>
public sealed class MemoryTokenStore : ITokenStore
{
    private readonly SemaphoreSlim _lock = new(1, 1);
    public StoredToken? Current { get; private set; }
    public IDisposable RefreshLock()
    {
        _lock.Wait();
        return new Releaser(_lock);
    }
    private sealed class Releaser(SemaphoreSlim l) : IDisposable { public void Dispose() => l.Release(); }
    public StoredToken? Load() => Current;
    public void Save(StoredToken token) => Current = token;
    public void Clear() => Current = null;
}
