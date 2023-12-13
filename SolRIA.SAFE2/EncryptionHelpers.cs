using System.Security.Cryptography;
using System.Text;

namespace SolRIA.SAFE;

/// <summary>
/// Helpers para encriptar e ler dados encriptados
/// </summary>
public class EncryptionHelpers
{
    /// <summary>
    /// Encripta o <paramref name="text"/> com a pass <paramref name="keyString"/> usando o método AES
    /// </summary>
    /// <param name="text">Texto a encriptar</param>
    /// <param name="keyString">pass para encriptar o <paramref name="text"/></param>
    /// <returns>Texto encriptado</returns>
    public static string Encrypt(string text, string keyString)
    {
        if (string.IsNullOrWhiteSpace(text))
            return text;

        var key = Encoding.UTF8.GetBytes(keyString);

        using var aesAlg = Aes.Create();
        using var encryptor = aesAlg.CreateEncryptor(key, aesAlg.IV);
        using var msEncrypt = new MemoryStream();
        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
        using (var swEncrypt = new StreamWriter(csEncrypt))
        {
            swEncrypt.Write(text);
        }

        var iv = aesAlg.IV;

        var decryptedContent = msEncrypt.ToArray();

        var result = new byte[iv.Length + decryptedContent.Length];

        Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
        Buffer.BlockCopy(decryptedContent, 0, result, iv.Length, decryptedContent.Length);

        return Convert.ToBase64String(result);
    }

    /// <summary>
    /// Lê o texto encriptado <paramref name="cipherText"/> com a pass <paramref name="keyString"/>
    /// </summary>
    /// <param name="cipherText">Texto encriptado</param>
    /// <param name="keyString">Pass usada para encriptar o texto no método <see cref="Encrypt(string, string)"/></param>
    /// <returns>Texto descodificado</returns>
    public static string Decrypt(string cipherText, string keyString)
    {
        if (string.IsNullOrWhiteSpace(cipherText))
            return null;

        try
        {
            var fullCipher = Convert.FromBase64String(cipherText);

            var iv = new byte[16];
            var cipher = new byte[fullCipher.Length - iv.Length];

            Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(fullCipher, iv.Length, cipher, 0, fullCipher.Length - iv.Length);
            var key = Encoding.UTF8.GetBytes(keyString);

            using var aesAlg = Aes.Create();
            using var decryptor = aesAlg.CreateDecryptor(key, iv);
            string result;
            using (var msDecrypt = new MemoryStream(cipher))
            using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
            using (var srDecrypt = new StreamReader(csDecrypt))
            {
                result = srDecrypt.ReadToEnd();
            }

            return result;
        }
        catch
        {
            return cipherText;
        }
    }
}
