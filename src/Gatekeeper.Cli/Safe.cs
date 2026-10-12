using System.Buffers;
using System.Text;

namespace Gatekeeper.Cli;

/// <summary>Neutralises text from the server before it reaches the terminal (escape sequences, bidi tricks).</summary>
public static class Safe
{
    public static string Text(string? value)
    {
        if (string.IsNullOrEmpty(value)) return value ?? "";
        var sb = new StringBuilder(value.Length);
        for (var i = 0; i < value.Length;)
        {
            if (Rune.DecodeFromUtf16(value.AsSpan(i), out var rune, out var used) != OperationStatus.Done)
            {
                sb.Append('�');
                i++;
                continue;
            }
            var v = rune.Value;
            var bad = Rune.IsControl(rune) || v is 0x061C or 0x200E or 0x200F or (>= 0x202A and <= 0x202E) or (>= 0x2066 and <= 0x2069);
            sb.Append(bad ? "�" : value.Substring(i, used));
            i += used;
        }
        return sb.ToString();
    }
}
