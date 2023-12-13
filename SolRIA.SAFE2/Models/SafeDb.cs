namespace SolRIA.SAFE.Models;

public class SafeDb
{
    public Config Config { get; set; }

    public SignatureConfig SignatureConfig { get; set; }

    public BasicAuth BasicAuth { get; set; }

    public Certificate[] Certificates { get; set; }
}
