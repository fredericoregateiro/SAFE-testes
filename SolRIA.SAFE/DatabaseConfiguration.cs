using SolRIA.Sign.SAFE.Interfaces;

namespace SAFE;

public class DatabaseConfiguration : IDatabaseConnection
{
    public string ConnectionString { get; set; }
}