using SAFE;

namespace SolRIA.SAFE.CLI;

public class Program
{
    /*
     * SolRIA.SAFE.CLI.exe "UpdateCredentials" -configFolder "E:\Faturação eletronica\Assinatura eletronica SAFE\tests" -credentialID "1229348b-5d7f-459c-b7e5-29648fb9ac8a" -accessToken "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJTQUZFIiwic3ViIjoiQkkxMjA2NjcxMSIsImF1ZCI6IkJJMTIwNjY3MTE1MTA5NTgzNjJTb2xSSUEiLCJpYXQiOjE2OTg5NDEyMDksImV4cCI6MTY5OTAyNzYwOSwidG9rZW5HdWlkIjoiNzJhYzUxY2ItOTFjNy00NWUzLTlhZTMtYWM0YzU4YmRiYTBjIiwiYWNjZXNzVG9rZW4iOnRydWUsInNhaWQiOiJmeUZ2UVRidkp5Y1BWVklEUU5tUTRvSko4bFE1Q09Id2t0eFFlU1Q0UFJFSFRRZ0JzaVFTMmc9PSJ9.tBC7y5KWoQte3TLhkW5t1Xd4FIysjrhiCA39CP06vNc" -refreshToken "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJTQUZFIiwic3ViIjoiQkkxMjA2NjcxMSIsImF1ZCI6IkJJMTIwNjY3MTE1MTA5NTgzNjJTb2xSSUEiLCJpYXQiOjE2OTg5NDEyMDksImV4cCI6MTcwMjc3MTE5OSwidG9rZW5HdWlkIjoiNDUyMTkzY2MtMTVlOC00YjIyLWJmZTAtMmZmYmVlZDk1ODNmIiwiYWNjZXNzVG9rZW4iOmZhbHNlLCJzYWlkIjoiZnlGdlFUYnZKeWNQVlZJRFFObVE0b0pKOGxRNUNPSHdrdHhRZVNUNFBSRUhUUWdCc2lRUzJnPT0ifQ.xwEQ88dH8kcCWZgJJn8ruCw1aZKfm11KRumvN0-ruLQ" -password "de4106a09a4e404793de07ed783fbde9"
     * SolRIA.SAFE.CLI.exe "UpdateCredentials" -configFolder "" -credentialID "" -accessToken "" -refreshToken "" -password "de4106a09a4e404793de07ed783fbde9"
     */

    [STAThread]
    public static void Main(string[] args)
    {
        if (args.Length <= 1)
        {
            Console.WriteLine("Argumentos inválidos");
            return;
        }

        // SolRIA.CLI option -parameters
        var opcao = args[0];

        var parameters = ReadParameters(args);
        switch (opcao)
        {
            case "UpdateCredentials":
                CallUpdateCredentials(parameters);
                break;
            default:
                break;
        }

        Console.WriteLine("Enter para terminar");
        Console.ReadLine();
    }

    private static void CallUpdateCredentials(Dictionary<string, string> parameters)
    {
        if (parameters.TryGetValue("-configFolder", out string folder) == false) return;
        if (parameters.TryGetValue("-credentialID", out string credentialID) == false) return;
        if (parameters.TryGetValue("-accessToken", out string accessToken) == false) return;
        if (parameters.TryGetValue("-refreshToken", out string refreshToken) == false) return;
        if (parameters.TryGetValue("-password", out string password) == false) return;

        Console.WriteLine("A invocar UpdateCredentials");

        var documentSign = new DocumentSign();
        documentSign.UpdateCredentials(
            configFolder: folder,
            credentialID: credentialID,
            accessToken: accessToken,
            refreshToken: refreshToken,
            password: password
        );
    }
    private static Dictionary<string, string> ReadParameters(string[] args)
    {
        var dictionary = new Dictionary<string, string>();
        for (int index = 1; index < args.Length; index += 2)
        {
            dictionary.Add(args[index], args[index + 1]);
        }

        return dictionary;
    }
}