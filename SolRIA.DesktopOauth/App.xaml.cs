using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace SolRIA.DesktopOauth
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            try
            {
                Current.DispatcherUnhandledException += Current_DispatcherUnhandledException;

                Log("A iniciar a aplicação");

                //init the main window
                var mainWindow = new MainWindow();

                var parameters = ReadParameters(e.Args);
                FillProperties(parameters);

                if (string.IsNullOrWhiteSpace(title) == false)
                    mainWindow.Title = title;
                if (width > 0)
                    mainWindow.Width = width;
                if (height > 0)
                    mainWindow.Height = height;
                if (fullscreen)
                    mainWindow.WindowState = WindowState.Maximized;

                mainWindow.Init(folder, nif, email, info, password, testMode);

                Current.MainWindow = mainWindow;
                //2C06FF182EEE4AC7AC1A260390FCC068

                Current.MainWindow.Show();
            }
            catch (Exception ex)
            {
                Log(ex);
            }
        }

        private void Current_DispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            Log(e.Exception);
        }

        string folder, nif, email, info, password, title;
        private double width, height;
        private bool fullscreen, testMode;
        private void FillProperties(Dictionary<string, string> parameters)
        {
            parameters.TryGetValue("-configFolder", out folder);
            parameters.TryGetValue("-nif", out nif);
            parameters.TryGetValue("-email", out email);
            parameters.TryGetValue("-info", out info);
            parameters.TryGetValue("-password", out password);
            parameters.TryGetValue("-title", out title);

            if (parameters.TryGetValue("-width", out string widthValue))
                double.TryParse(widthValue, out width);

            if (parameters.TryGetValue("-height", out string heightValue))
                double.TryParse(heightValue, out height);

            testMode = parameters.ContainsKey("-testMode");
            fullscreen = parameters.ContainsKey("-fullscreen");
        }
        private Dictionary<string, string> ReadParameters(string[] args)
        {
            var dictionary = new Dictionary<string, string>();
            for (int index = 0; index < args.Length; index++)
            {
                // get the key
                var key = args[index];

                // check if we have a next argument to parse
                if (args.Length > index + 1)
                {
                    // read the next argument
                    var nextArg = args[index + 1];

                    // check if the next argument is a key
                    if (string.IsNullOrWhiteSpace(nextArg) == false && nextArg.StartsWith("-"))
                    {
                        // the next argument is a key, add the current key with no value
                        dictionary.Add(key, string.Empty);
                        continue;
                    }

                    // add the key and the argument
                    dictionary.Add(key, nextArg);
                    index++;
                    continue;
                }

                // we don't have a next argument after the key, just add the key
                dictionary.Add(key, string.Empty);
            }

            return dictionary;
        }

        public static void Log(string message)
        {
            message += Environment.NewLine;

            File.AppendAllText(Path.Combine(Path.GetTempPath(), "safe-logs.txt"), message);
        }

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
}
