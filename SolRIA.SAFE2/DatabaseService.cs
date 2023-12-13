using SolRIA.SAFE.Interfaces;
using SolRIA.SAFE.Models;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml.Serialization;
using System.Xml;

namespace SolRIA.SAFE;

public class DatabaseService : IDatabaseService
{
    private readonly string _dbFile;
    private SafeDb _safeDb;
    public DatabaseService(string configurationFolder)
    {
        _dbFile = Path.Combine(configurationFolder, "db.xml");
    }

    public void Init()
    {
        // create a new file
        if (File.Exists(_dbFile) == false)
        {
            _safeDb = new SafeDb
            {
                BasicAuth = new BasicAuth(),
                Config = new Config(),
                SignatureConfig = new SignatureConfig(),
                Certificates = Array.Empty<Certificate>()
            };

            SerializeXml(_safeDb, _dbFile);

            return;
        }

        // read the existing file
        _safeDb = DeserializeXml<SafeDb>(_dbFile);
    }

    private T DeserializeXml<T>(string xmlFileName)
    {
        if (File.Exists(xmlFileName) == false)
            return default;

        TextReader tw = null;
        try
        {
            tw = new StreamReader(xmlFileName, Encoding.UTF8);

            var x = new XmlSerializer(typeof(T));
            var config = (T)x.Deserialize(tw);

            return config;

        }
        catch (Exception)
        {
            return default;
        }
        finally
        {
            if (tw != null)
            {
                tw.Close();
                tw.Dispose();
            }
        }
    }

    private void SerializeXml<T>(T content, string filename, XmlWriterSettings settings = null)
    {
        settings ??= new XmlWriterSettings
        {
            Encoding = Encoding.UTF8,
            Indent = true,
            Async = true
        };

        using var writer = XmlWriter.Create(filename, settings);
        var x = new XmlSerializer(typeof(T));
        x.Serialize(writer, content);
        writer.Flush();
    }

    public Config LoadConfig(string password)
    {
        _safeDb.Config.AccessToken = EncryptionHelpers.Decrypt(_safeDb.Config.AccessToken, password);
        _safeDb.Config.RefreshToken = EncryptionHelpers.Decrypt(_safeDb.Config.RefreshToken, password);

        return _safeDb.Config;
    }

    public Config UpdateConfig(Config config, string password)
    {
        // encrypt the tokens
        _safeDb.Config = config;
        _safeDb.Config.AccessToken = EncryptionHelpers.Encrypt(_safeDb.Config.AccessToken, password);
        _safeDb.Config.RefreshToken = EncryptionHelpers.Encrypt(_safeDb.Config.RefreshToken, password);

        // save the tokens
        SerializeXml(_safeDb, _dbFile);

        // return the new config
        return LoadConfig(password);
    }

    public SignatureConfig LoadSignatureConfig()
    {
        return _safeDb.SignatureConfig;
    }

    public void UpdateSignatureConfig(SignatureConfig signatureConfig)
    {
        _safeDb.SignatureConfig = signatureConfig;

        SerializeXml(_safeDb, _dbFile);
    }

    public BasicAuth LoadBasicAuth()
    {
        return _safeDb.BasicAuth;
    }

    public void UpdateBasicAuth(BasicAuth basicAuth)
    {
        _safeDb.BasicAuth = basicAuth;

        SerializeXml(_safeDb, _dbFile);
    }

    public List<X509Certificate2> LoadCertificates()
    {
        if (_safeDb.Certificates == null || _safeDb.Certificates.Any() == false)
            return new List<X509Certificate2>();

        //Create new X509Certificate2 with the root certificate
        return _safeDb.Certificates.Select(c => new X509Certificate2(Convert.FromBase64String(c.CertificateData))).ToList();
    }

    public List<X509Certificate2> UpdateCertificates(Certificate[] certificates)
    {
        _safeDb.Certificates = certificates;

        SerializeXml(_safeDb, _dbFile);

        return LoadCertificates();
    }

    public void ClearCertificates()
    {
        _safeDb.Certificates = Array.Empty<Certificate>();

        SerializeXml(_safeDb, _dbFile);
    }
}
