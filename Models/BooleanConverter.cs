using System.Text.Json;
using System.Text.Json.Serialization;

namespace FraudDetection.ML.Models;

/// <summary>
/// Custom JSON converter that handles boolean values stored as:
/// - true/false (proper booleans)
/// - 0/1 (numbers)
/// - "true"/"false" (strings)
/// - "0"/"1" (string numbers)
/// </summary>
public class BooleanConverter : JsonConverter<bool>
{
    public override bool Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        switch (reader.TokenType)
        {
            case JsonTokenType.True:
                return true;
            case JsonTokenType.False:
                return false;
            case JsonTokenType.Number:
                return reader.GetInt32() != 0;
            case JsonTokenType.String:
                var stringValue = reader.GetString();
                if (string.IsNullOrEmpty(stringValue))
                    return false;

                // Handle "true"/"false" strings
                if (bool.TryParse(stringValue, out var boolResult))
                    return boolResult;

                // Handle "0"/"1" strings
                if (int.TryParse(stringValue, out var intResult))
                    return intResult != 0;

                return false;
            default:
                throw new JsonException($"Unable to convert {reader.TokenType} to Boolean");
        }
    }

    public override void Write(Utf8JsonWriter writer, bool value, JsonSerializerOptions options)
    {
        writer.WriteBooleanValue(value);
    }
}
