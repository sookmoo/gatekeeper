using System.Text.Json;
using System.Text.Json.Serialization;
using Gatekeeper.Domain;

namespace Gatekeeper.Api;

/// <summary>
/// The kind is exactly the word person, test or shared (any case) in JSON: no numbers and no comma lists, which the
/// built-in enum converter would accept as flag combinations.
/// </summary>
public sealed class UserKindConverter : JsonConverter<UserKind>
{
    public override UserKind Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.String)
        {
            var text = reader.GetString();
            if (string.Equals(text, "person", StringComparison.OrdinalIgnoreCase)) return UserKind.Person;
            if (string.Equals(text, "test", StringComparison.OrdinalIgnoreCase)) return UserKind.Test;
            if (string.Equals(text, "shared", StringComparison.OrdinalIgnoreCase)) return UserKind.Shared;
        }
        throw new JsonException("kind must be person, test or shared.");
    }

    public override void Write(Utf8JsonWriter writer, UserKind value, JsonSerializerOptions options) =>
        writer.WriteStringValue(value.ToString().ToLowerInvariant());
}
