using System.Net.Http;

namespace SolRIA.SAFE2;

public class LoggingHandler : DelegatingHandler
{
    private readonly bool _logToFile;
    public LoggingHandler(HttpMessageHandler innerHandler, bool logToFile)
        : base(innerHandler)
    {
        _logToFile = logToFile;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (_logToFile)
        {
            LogService.Log("Request:");
            LogService.Log(request.ToString());
            if (request.Content != null)
            {
                LogService.Log(await request.Content.ReadAsStringAsync());
            }
        }

        HttpResponseMessage response = await base.SendAsync(request, cancellationToken);

        if (_logToFile)
        {
            LogService.Log("Response:");
            LogService.Log(response.ToString());
            if (response.Content != null)
            {
                LogService.Log(await response.Content.ReadAsStringAsync());
            }
        }

        return response;
    }
}