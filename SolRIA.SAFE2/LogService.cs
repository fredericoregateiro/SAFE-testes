using System.Globalization;

namespace SolRIA.SAFE2;

/// <summary>
/// Log Helper
/// </summary>
public static class LogService
{
    /// <summary>
    /// Log a message to the log file
    /// </summary>
    /// <param name="message">The message to log</param>
    public static void Log(string message)
    {
        File.AppendAllText(Path.Combine(Path.GetTempPath(), "safe-requests-logs.txt"), 
            string.Format(CultureInfo.CurrentCulture, "{0:yyyy-MM-dd HH:mm:ss.fff}: {1}{2}", DateTime.Now, message, Environment.NewLine));
    }

    /// <summary>
    /// Log exception details to the log file
    /// </summary>
    /// <param name="exception">The exception to log</param>
    public static void Log(Exception exception)
    {
        Log(exception.ToString());
        var inner = exception.InnerException;
        while (inner != null)
        {
            Log(inner.Message);
            inner = inner.InnerException;
        }
    }
}
