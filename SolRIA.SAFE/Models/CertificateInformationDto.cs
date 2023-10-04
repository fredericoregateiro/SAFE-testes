namespace SolRIA.Sign.SAFE.Models;

public sealed class CertificateInformationDto
{
    [System.Text.Json.Serialization.JsonPropertyName("certificates")]
    public ICollection<string> Certificates { get; set; } = new System.Collections.ObjectModel.Collection<string>();
}