namespace Gatekeeper.Cli;

/// <summary>Reads a password: the first line of stdin when piped, otherwise a hidden prompt. Never taken from arguments.</summary>
public static class Secrets
{
    public static string? Read(string prompt, bool confirm)
    {
        if (Console.IsInputRedirected) return Console.In.ReadLine();
        var first = Prompt(prompt);
        if (confirm && Prompt("Repeat password: ") != first) throw new CliException(1, "Passwords do not match.");
        return first;
    }

    private static string Prompt(string prompt)
    {
        Console.Error.Write(prompt);
        var text = new System.Text.StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter) break;
            if (key.Key == ConsoleKey.Backspace) { if (text.Length > 0) text.Length--; }
            else if (!char.IsControl(key.KeyChar)) text.Append(key.KeyChar);
        }
        Console.Error.WriteLine();
        return text.ToString();
    }
}
