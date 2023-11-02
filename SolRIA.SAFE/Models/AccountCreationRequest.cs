namespace SolRIA.SAFE.Models;

public class AccountCreationRequest
{
    public string NIF { get; set; }
    public string Info { get; set; }
    public string Email { get; set; }
    public string Valid { get; set; }
    public string Max { get; set; } = "450000";

    public static string FillValid()
    {
        return DateTime.Now.AddDays(45).ToString("yyyy-MM-dd");
    }
}
