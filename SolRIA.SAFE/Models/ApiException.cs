using System.Net;

namespace SolRIA.Sign.SAFE.Models;

public class ApiException : Exception
{
    public HttpStatusCode StatusCode { get; private set; }

    public string Response { get; private set; }

    public IReadOnlyDictionary<string, IEnumerable<string>> Headers { get; private set; }

    public ApiException(string message, HttpStatusCode statusCode, string response, IReadOnlyDictionary<string, IEnumerable<string>> headers, Exception innerException)
        : base(message + "\n\nStatus: " + (int)statusCode + "\nResponse: \n" + ((response == null) ? "(null)" : response[..Math.Min(512, response.Length)]), innerException)
    {
        StatusCode = statusCode;
        Response = response;
        Headers = headers;
    }

    public override string ToString()
    {
        var headers = $"Headers:{Environment.NewLine}";
        foreach (var h in Headers)
        {
            headers += $"{h.Key}: ";
            foreach (var value in h.Value)
            {
                headers += $" {value}";
            }
            headers += Environment.NewLine;
        }
        return string.Format("HTTP Response: \n\n{0}\n\n{1}\n\n{2}", Response, base.ToString(), headers);
    }
}

public sealed class ApiException<TResult> : ApiException
{
    public TResult Result { get; private set; }

    public ApiException(string message, HttpStatusCode statusCode, string response, IReadOnlyDictionary<string, IEnumerable<string>> headers, TResult result, Exception innerException)
        : base(message, statusCode, response, headers, innerException)
    {
        Result = result;
    }
}