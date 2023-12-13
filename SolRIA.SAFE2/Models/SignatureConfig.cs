namespace SolRIA.SAFE.Models;

public class SignatureConfig
{
    public string ContactInfo { get; set; }
    public string LocationInfo { get; set; }
    public string Reason { get; set; }
    public string TimeStampServer { get; set; }
    public bool EnableLtv { get; set; }
    public float SignatureX { get; set; }
    public float SignatureY { get; set; }
    public float SignatureWidth { get; set; }
    public float SignatureHeight { get; set; }
    public byte[] SignatureImage { get; set; }
}
