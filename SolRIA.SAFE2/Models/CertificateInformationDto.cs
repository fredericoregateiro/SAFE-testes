namespace SolRIA.SAFE.Models;

public sealed class CertificateInformationDto
{
    [Newtonsoft.Json.JsonProperty("certificates")]
    public ICollection<string> Certificates { get; set; } = new System.Collections.ObjectModel.Collection<string>();
}