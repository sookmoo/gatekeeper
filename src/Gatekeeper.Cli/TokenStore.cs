using System.Text.Json;

namespace Gatekeeper.Cli;

/// <summary>A saved login. The token is only ever sent to <see cref="Origin"/>.</summary>
public sealed record StoredToken(string Origin, string AccessToken, DateTimeOffset ExpiresAt, string Username);

public interface ITokenStore
{
    StoredToken? Load();
    void Save(StoredToken token);
    void Clear();
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
    public StoredToken? Current { get; private set; }
    public StoredToken? Load() => Current;
    public void Save(StoredToken token) => Current = token;
    public void Clear() => Current = null;
}
