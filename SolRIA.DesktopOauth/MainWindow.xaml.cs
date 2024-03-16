using Microsoft.Web.WebView2.Core;
using SAFE;
using SolRIA.SAFE.Models;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Windows;

namespace SolRIA.DesktopOauth
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }
        private readonly string webviewDownload = "https://go.microsoft.com/fwlink/p/?LinkId=2124703";

        public MessageResult MessageResult { get; set; }

        private string _configFolder, _nif, _email, _info, _password;
        private bool _testMode, _logUrl;
        private DocumentSign _documentSign;
        public void Init(string configFolder, string nif, string email, string info, string password, bool testMode, bool logUrl)
        {
            _configFolder = configFolder;
            _nif = nif;
            _email = email;
            _info = info;
            _password = password;
            _testMode = testMode;
            _logUrl = logUrl;
        }

        private async void Window_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                progress.Visibility = Visibility.Collapsed;
                webview2Download.Visibility = Visibility.Collapsed;

                InstallType installType = await CheckWebViewInstall();

                if (installType == InstallType.NotInstalled)
                {
                    await LoadAndInstallWebView();
                }

                _documentSign = new DocumentSign();
                var url = _documentSign.BuildAuthUrl(_configFolder, _nif, _email, _info, "", _testMode);

                //web.Address = url;
                //web.Navigate(url);
                web.Source = new Uri(url);

                //web.AddressChanged += Web_AddressChanged;
                //web.Navigated += Web_Navigated;
                web.NavigationCompleted += Web_NavigationCompleted;

                //addressBarText.Text = web.Address;
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
                App.Log(ex);
            }
        }

        private void Hyperlink_Click(object sender, RoutedEventArgs e)
        {
            Process.Start(webviewDownload);
        }

        private async Task<InstallType> CheckWebViewInstall()
        {
            var version = string.Empty;

            try
            {
                await web.EnsureCoreWebView2Async();
                version = CoreWebView2Environment.GetAvailableBrowserVersionString();
            }
            catch (Exception ex)
            {
                App.Log(ex);
            }

            webVersion.Text = string.IsNullOrWhiteSpace(version) ? "Webview2 não está instalado" : $"v {version}";

            var installType = GetInstallVersion(version);
            return installType;
        }

        //private async void Web_AddressChanged(object sender, DependencyPropertyChangedEventArgs e)
        //{
        //    addressBarText.Text = web.Address;

        //    if (web.Address.Contains("/Authorized#"))
        //    {
        //        MessageResult = await _documentSign.CreateAccountAsync(_configFolder, web.Address, _password, _testMode);

        //        web.Dispose();

        //        Close();
        //    }
        //}

        //private async void Web_Navigated(object sender, System.Windows.Navigation.NavigationEventArgs e)
        //{
        //    var url = web.Source.ToString();
        //    addressBarText.Text = url;

        //    if (url.Contains("/Authorized#"))
        //    {
        //        MessageResult = await _documentSign.CreateAccountAsync(_configFolder, url, _password, _testMode);

        //        web.Dispose();

        //        Close();
        //    }
        //}

        private async void Web_NavigationCompleted(object sender, CoreWebView2NavigationCompletedEventArgs e)
        {
            try
            {
                var url = web.Source.ToString();
                addressBarText.Text = url;

                if (_logUrl)
                {
                    App.Log(url);
                }

                if (url.Contains("/Authorized#"))
                {
                    MessageResult = await _documentSign.CreateAccountAsync(_configFolder, url, _password, _testMode, _logUrl);

                    if (MessageResult == null || MessageResult.Success == false)
                    {
                        MessageBox.Show(this, MessageResult?.Message ?? "Não foi possível ler o resultado da autenticação", "Erro", MessageBoxButton.OK, MessageBoxImage.Error);
                    }

                    web.Dispose();

                    Close();
                }
            }
            catch (Exception ex)
            {
                App.Log(ex);
            }
        }

        private InstallType GetInstallVersion(string version)
        {
            return version switch
            {
                _ when version.Contains("dev") => InstallType.EdgeChromiumDev,
                _ when version.Contains("beta") => InstallType.EdgeChromiumBeta,
                _ when version.Contains("canary") => InstallType.EdgeChromiumCanary,
                _ when string.IsNullOrWhiteSpace(version) == false => InstallType.WebView2,
                _ => InstallType.NotInstalled
            };
        }

        private async Task LoadAndInstallWebView()
        {
            progress.Visibility = Visibility.Visible;

            try
            {
                var client = new HttpClient();
                var contentData = await client.GetByteArrayAsync(webviewDownload);

                var filename = Path.Combine(Path.GetTempPath(), "MicrosoftEdgeWebview2Setup.exe");

                File.WriteAllBytes(filename, contentData);

                Process.Start(filename, "/silent /install");
            }
            catch (Exception ex)
            {
                App.Log(ex);
            }

            InstallType installType = await CheckWebViewInstall();

            if (installType == InstallType.NotInstalled)
            {
                webview2Download.Visibility = Visibility.Visible;
            }

            progress.Visibility = Visibility.Collapsed;
        }
    }
}

public enum InstallType
{
    WebView2, EdgeChromiumBeta, EdgeChromiumCanary, EdgeChromiumDev, NotInstalled
}