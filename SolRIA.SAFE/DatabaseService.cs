using Dapper;
using Microsoft.Data.Sqlite;
using SolRIA.SAFE.Interfaces;
using SolRIA.Sign.SAFE.Interfaces;
using SolRIA.Sign.SAFE.Models;
using System.Security.Cryptography.X509Certificates;

namespace SolRIA.SAFE;

public class DatabaseService : IDatabaseService
{
    private readonly int VERSION = 1;
    private readonly IDatabaseConnection _configuration;
    public DatabaseService(IDatabaseConnection configuration)
    {
        _configuration = configuration;
    }

    public void Init()
    {
        using var connection = new SqliteConnection(_configuration.ConnectionString);
        connection.Open();

        int versionId = 0;
        var hasTables = connection.ExecuteScalar<int>("SELECT COUNT(*) FROM sqlite_schema WHERE name = 'db_version';");
        if (hasTables == 0)
        {
        }
        else
        {
            versionId = connection.ExecuteScalar<int>("SELECT Id FROM `db_version` ORDER BY Id DESC;");
        }

        // run the versions files
    }

    public Config LoadConfig(string password)
    {
        using var connection = new SqliteConnection(_configuration.ConnectionString);

        return LoadConfig(password, connection);
    }

    private Config LoadConfig(string password, SqliteConnection connection)
    {
        var config = connection.QueryFirstOrDefault<Config>("SELECT * FROM config;");

        config ??= new Config();

        config.AccessToken = EncryptionHelpers.Decrypt(config.AccessToken, password);
        config.RefreshToken = EncryptionHelpers.Decrypt(config.RefreshToken, password);

        return config;
    }

    public Config UpdateConfig(Config config, string password)
    {
        using var connection = new SqliteConnection(_configuration.ConnectionString);

        // encrypt the tokens
        config.AccessToken = EncryptionHelpers.Encrypt(config.AccessToken, password);
        config.RefreshToken = EncryptionHelpers.Encrypt(config.RefreshToken, password);

        // save the tokens
        if (config.Id == 0)
        {
            connection.Execute("""
                INSERT INTO config 
                (access_token,refresh_token,credential_id,cert_status,cert_algo,cert_len) VALUES 
                (@AccessToken,@RefreshToken,@CredentialID,@CertStatus,@CertAlgo,@CertLen);
            """, config);
        }
        else
        {
            connection.Execute("""
                UPDATE config SET 
                access_token=@AccessToken, refresh_token=@RefreshToken, credential_id=@CredentialID,
                cert_status=@CertStatus, cert_algo=@CertAlgo, cert_len=@CertLen
                WHERE id=@Id;
            """, config);
        }

        // return the new config
        return LoadConfig(password, connection);
    }

    public SignatureConfig LoadSignatureConfig()
    {
        using var connection = new SqliteConnection(_configuration.ConnectionString);

        var config = connection.QueryFirstOrDefault<SignatureConfig>("SELECT * FROM signature;");

        return config ??= new SignatureConfig();
    }

    public void UpdateSignatureConfig(SignatureConfig signatureConfig)
    {
        using var connection = new SqliteConnection(_configuration.ConnectionString);
        connection.Open();
        var transaction = connection.BeginTransaction();

        try
        {
            connection.Execute("DELETE FROM signature;", transaction);

            connection.Execute("""
                INSERT INTO signature 
                (contact_info,location_info,reason,time_stamp_server,enable_ltv,signature_x,signature_y,signature_width,signature_height,signature_image) VALUES 
                (@ContactInfo,@LocationInfo,@Reason,@TimeStampServer,@EnableLtv,@SignatureX,@SignatureY,@SignatureWidth,@SignatureHeight,@SignatureImage);
            """, signatureConfig, transaction);

            transaction.Commit();
        }
        catch
        {
            transaction.Rollback();
            throw;
        }
    }

    public BasicAuth LoadBasicAuth()
    {
        using var connection = new SqliteConnection(_configuration.ConnectionString);

        return connection.QueryFirstOrDefault<BasicAuth>("SELECT * FROM basic_auth;");
    }

    public void UpdateBasicAuth(BasicAuth basicAuth)
    {
        using var connection = new SqliteConnection(_configuration.ConnectionString);
        connection.Open();
        var transaction = connection.BeginTransaction();

        try
        {
            connection.Execute("DELETE FROM basic_auth;", transaction);

            connection.Execute("""
            INSERT INTO basic_auth 
            (client_name,client_id,username,password) VALUES 
            (@ClientName,@ClientId,@Username,@Password);
            """, basicAuth, transaction);

            transaction.Commit();
        }
        catch
        {
            transaction.Rollback();
            throw;
        }
    }

    public List<X509Certificate2> LoadCertificates()
    {
        using var connection = new SqliteConnection(_configuration.ConnectionString);

        var certificates = connection.Query<byte[]>("""
            SELECT certificate_data FROM certificates ORDER BY `order`;
        """);

        if (certificates == null || certificates.Any() == false)
            return new List<X509Certificate2>();

        //Create new X509Certificate2 with the root certificate
        return certificates.Select(c => new X509Certificate2(c)).AsList();
    }

    public List<X509Certificate2> UpdateCertificates(IEnumerable<Certificate> certificates)
    {
        var connection = new SqliteConnection(_configuration.ConnectionString);
        connection.Open();
        var transaction = connection.BeginTransaction();

        try
        {
            connection.Execute("DELETE FROM certificates;", transaction);

            connection.Execute("""
                INSERT INTO certificates 
                (certificate_data, `order`) VALUES 
                (@CertificateData, @Order);
            """, certificates, transaction);

            transaction.Commit();
        }
        catch
        {
            transaction.Rollback();
            throw;
        }

        return LoadCertificates();
    }
}
