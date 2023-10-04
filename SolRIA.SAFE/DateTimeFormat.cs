using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SolRIA.Sign.SAFE;

public class DateTimeFormat : JsonConverter<DateTime>
{
    public override DateTime Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        return DateTime.ParseExact(reader.GetString(), new string[] { "yyyy-MM-dd HH:mm:ss.fff" }, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);
    }

    public override void Write(Utf8JsonWriter writer, DateTime value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.ToString());
    }
}