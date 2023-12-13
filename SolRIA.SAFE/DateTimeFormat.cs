using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SolRIA.Sign.SAFE;

public class DateTimeFormat : JsonConverter<DateTime>
{
    public override DateTime Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var dt = reader.GetString().Substring(0, 19);
        return DateTime.ParseExact(dt, new string[] { "yyyy-MM-dd HH:mm:ss" }, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);
    }

    public override void Write(Utf8JsonWriter writer, DateTime value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.ToString());
    }
}