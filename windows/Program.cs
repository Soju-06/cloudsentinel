using System;
using System.Drawing;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

[assembly: AssemblyTitle("CloudSentinel")]
[assembly: AssemblyDescription("Cloud security monitoring and threat detection console")]
[assembly: AssemblyProduct("CloudSentinel")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

namespace CloudSentinel
{
    internal static class Program
    {
        [STAThread]
        private static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm(args));
        }
    }

    internal sealed class MainForm : Form
    {
        private readonly WebView2 _browser;
        private readonly bool _devTools;
        private readonly bool _probe;
        private string _serverUrl;
        private string _token;
        private LocalServer _server;

        public MainForm(string[] args)
        {
            _devTools = Array.IndexOf(args, "--devtools") >= 0;
            _probe = Array.IndexOf(args, "--probe") >= 0;

            for (int index = 0; index < args.Length; index++)
            {
                if (args[index] == "--server" && index + 1 < args.Length)
                {
                    _serverUrl = args[++index];
                }
                else if (args[index] == "--token" && index + 1 < args.Length)
                {
                    _token = args[++index];
                }
            }

            // The WebView2 control applies the monitor scale factor itself.
            // Letting WinForms autoscale the form as well would scale the
            // browser surface twice (at 125% the page would render 25% wider
            // than the window).
            AutoScaleMode = AutoScaleMode.None;

            Rectangle workArea = Screen.FromPoint(Cursor.Position).WorkingArea;

            Text = "CloudSentinel";
            Width = Math.Max(900, Math.Min(1440, (int)(workArea.Width * 0.92)));
            Height = Math.Max(600, Math.Min(940, (int)(workArea.Height * 0.94)));
            MinimumSize = new Size(880, 600);
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = Color.FromArgb(5, 8, 16);

            try
            {
                Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
            }
            catch
            {
                // A missing icon must never stop the app from starting.
            }

            TryEnableDarkTitleBar();

            _browser = new WebView2();
            _browser.Dock = DockStyle.Fill;
            _browser.DefaultBackgroundColor = Color.FromArgb(5, 8, 16);
            Controls.Add(_browser);

            Load += OnLoaded;
            FormClosed += OnClosed;
        }

        private void TryEnableDarkTitleBar()
        {
            try
            {
                int enabled = 1;
                DwmSetWindowAttribute(Handle, 20, ref enabled, sizeof(int));
            }
            catch
            {
                // Older Windows builds keep the default title bar.
            }
        }

        [System.Runtime.InteropServices.DllImport("dwmapi.dll")]
        private static extern int DwmSetWindowAttribute(
            IntPtr hwnd,
            int attribute,
            ref int value,
            int size
        );

        private async void OnLoaded(object sender, EventArgs e)
        {
            string webRoot = Path.Combine(Application.StartupPath, "web");
            if (!File.Exists(Path.Combine(webRoot, "index.html")))
            {
                MessageBox.Show(
                    "The web assets are missing.\n\nExpected:\n" + webRoot,
                    "CloudSentinel",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
                Close();
                return;
            }

            try
            {
                _server = new LocalServer(webRoot);
                int port = _server.Start();

                string dataDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "CloudSentinel",
                    "WebView2"
                );
                Directory.CreateDirectory(dataDir);

                CoreWebView2Environment environment =
                    await CoreWebView2Environment.CreateAsync(null, dataDir);
                await _browser.EnsureCoreWebView2Async(environment);

                CoreWebView2Settings settings = _browser.CoreWebView2.Settings;
                settings.AreDevToolsEnabled = _devTools;
                settings.AreDefaultContextMenusEnabled = _devTools;
                settings.IsStatusBarEnabled = false;
                settings.AreHostObjectsAllowed = false;
                settings.IsZoomControlEnabled = true;

                _browser.CoreWebView2.NewWindowRequested += delegate(
                    object newWindowSender,
                    CoreWebView2NewWindowRequestedEventArgs newWindowArgs
                )
                {
                    newWindowArgs.Handled = true;
                };

                _browser.Source = new Uri(BuildStartUrl(port));

                if (_probe)
                {
                    await RunProbe();
                }
            }
            catch (Exception error)
            {
                MessageBox.Show(
                    "CloudSentinel could not start its desktop shell.\n\n" +
                        error.Message +
                        "\n\nIf the WebView2 Runtime is missing, install it from:\n" +
                        "https://developer.microsoft.com/microsoft-edge/webview2/",
                    "CloudSentinel",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
                Close();
            }
        }

        /// <summary>
        /// Diagnostic mode used by the build to confirm that the browser
        /// viewport matches the window at any display scale factor.
        /// </summary>
        private async Task RunProbe()
        {
            await Task.Delay(9000);
            string result = await _browser.ExecuteScriptAsync(
                "JSON.stringify({w:window.innerWidth,h:window.innerHeight,"
                    + "dpr:window.devicePixelRatio,"
                    + "cw:document.documentElement.clientWidth,"
                    + "ch:document.documentElement.clientHeight})"
            );
            string path = Path.Combine(Path.GetTempPath(), "cloudsentinel-probe.txt");
            File.WriteAllText(
                path,
                result
                    + Environment.NewLine
                    + "formClient=" + ClientSize.Width + "x" + ClientSize.Height
                    + Environment.NewLine
                    + "window=" + Width + "x" + Height
            );
            Application.Exit();
        }

        private string BuildStartUrl(int port)
        {
            string url = "http://127.0.0.1:" + port + "/";
            if (string.IsNullOrEmpty(_serverUrl))
            {
                return url;
            }

            url += "?server=" + Uri.EscapeDataString(_serverUrl);
            if (!string.IsNullOrEmpty(_token))
            {
                url += "&token=" + Uri.EscapeDataString(_token);
            }
            return url;
        }

        protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
        {
            if (keyData == Keys.F5 && _browser.CoreWebView2 != null)
            {
                _browser.CoreWebView2.Reload();
                return true;
            }
            if (_devTools && keyData == (Keys.Control | Keys.Shift | Keys.I))
            {
                if (_browser.CoreWebView2 != null)
                {
                    _browser.CoreWebView2.OpenDevToolsWindow();
                }
                return true;
            }
            return base.ProcessCmdKey(ref msg, keyData);
        }

        private void OnClosed(object sender, FormClosedEventArgs e)
        {
            if (_server != null)
            {
                _server.Stop();
            }
        }
    }

    /// <summary>
    /// Minimal static file server bound to loopback. Avoids HttpListener URL ACLs
    /// (which would require administrator rights) while giving WebView2 a normal
    /// http:// origin for Flutter and the API client.
    /// </summary>
    internal sealed class LocalServer
    {
        private readonly string _root;
        private TcpListener _listener;
        private Thread _thread;
        private volatile bool _running;

        public LocalServer(string root)
        {
            _root = Path.GetFullPath(root);
        }

        public int Start()
        {
            for (int port = 47831; port < 47901; port++)
            {
                try
                {
                    TcpListener candidate = new TcpListener(IPAddress.Loopback, port);
                    candidate.Start();
                    _listener = candidate;
                    break;
                }
                catch (SocketException)
                {
                    // Port in use; try the next one.
                }
            }

            if (_listener == null)
            {
                throw new InvalidOperationException("No free local port between 47831 and 47900.");
            }

            _running = true;
            _thread = new Thread(AcceptLoop);
            _thread.IsBackground = true;
            _thread.Start();

            return ((IPEndPoint)_listener.LocalEndpoint).Port;
        }

        public void Stop()
        {
            _running = false;
            try
            {
                if (_listener != null)
                {
                    _listener.Stop();
                }
            }
            catch
            {
                // Best effort during shutdown.
            }
        }

        private void AcceptLoop()
        {
            while (_running)
            {
                try
                {
                    TcpClient client = _listener.AcceptTcpClient();
                    ThreadPool.QueueUserWorkItem(HandleClient, client);
                }
                catch
                {
                    if (!_running)
                    {
                        break;
                    }
                }
            }
        }

        private void HandleClient(object state)
        {
            using (TcpClient client = (TcpClient)state)
            {
                try
                {
                    client.ReceiveTimeout = 5000;
                    client.SendTimeout = 30000;
                    client.NoDelay = true;

                    string requestLine = ReadRequest(client.GetStream());
                    if (string.IsNullOrEmpty(requestLine))
                    {
                        return;
                    }

                    string[] parts = requestLine.Split(' ');
                    if (parts.Length < 2 || parts[0] != "GET")
                    {
                        WriteResponse(client.GetStream(), 405, "text/plain", Encoding.UTF8.GetBytes("Method Not Allowed"));
                        return;
                    }

                    string rawPath = parts[1];
                    int queryIndex = rawPath.IndexOf('?');
                    if (queryIndex >= 0)
                    {
                        rawPath = rawPath.Substring(0, queryIndex);
                    }
                    rawPath = Uri.UnescapeDataString(rawPath);
                    if (rawPath == "/" || rawPath.Length == 0)
                    {
                        rawPath = "/index.html";
                    }

                    string relative = rawPath.TrimStart('/').Replace('/', Path.DirectorySeparatorChar);
                    string fullPath = Path.GetFullPath(Path.Combine(_root, relative));

                    if (
                        !fullPath.Equals(_root, StringComparison.OrdinalIgnoreCase) &&
                        !fullPath.StartsWith(_root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                    )
                    {
                        WriteResponse(client.GetStream(), 403, "text/plain", Encoding.UTF8.GetBytes("Forbidden"));
                        return;
                    }

                    if (!File.Exists(fullPath))
                    {
                        // Flutter uses a single-page navigation model.
                        fullPath = Path.Combine(_root, "index.html");
                    }

                    byte[] body = File.ReadAllBytes(fullPath);
                    WriteResponse(client.GetStream(), 200, ContentType(fullPath), body);
                }
                catch
                {
                    // Drop malformed or aborted requests; the UI retries as needed.
                }
            }
        }

        private static string ReadRequest(NetworkStream stream)
        {
            // Drain the full header block before answering. Replying while the
            // client is still writing headers can trigger a TCP reset and
            // truncate large assets such as main.dart.js.
            byte[] buffer = new byte[8192];
            StringBuilder builder = new StringBuilder();
            int total = 0;

            while (total < 32768)
            {
                int read = stream.Read(buffer, 0, buffer.Length);
                if (read <= 0)
                {
                    break;
                }

                total += read;
                builder.Append(Encoding.ASCII.GetString(buffer, 0, read));

                string text = builder.ToString();
                if (text.Contains("\r\n\r\n"))
                {
                    break;
                }
            }

            string request = builder.ToString();
            int lineEnd = request.IndexOf("\r\n", StringComparison.Ordinal);
            return lineEnd > 0 ? request.Substring(0, lineEnd) : request;
        }

        private static void WriteResponse(NetworkStream stream, int status, string contentType, byte[] body)
        {
            string reason = status == 200 ? "OK" : status == 403 ? "Forbidden" : "Error";
            string headers =
                "HTTP/1.1 " + status + " " + reason + "\r\n"
                + "Content-Type: " + contentType + "\r\n"
                + "Content-Length: " + body.Length + "\r\n"
                + "Cache-Control: no-store\r\n"
                + "X-Content-Type-Options: nosniff\r\n"
                + "Connection: close\r\n\r\n";

            byte[] headerBytes = Encoding.ASCII.GetBytes(headers);
            stream.Write(headerBytes, 0, headerBytes.Length);
            stream.Write(body, 0, body.Length);
            stream.Flush();
        }

        private static string ContentType(string path)
        {
            switch (Path.GetExtension(path).ToLowerInvariant())
            {
                case ".html":
                    return "text/html; charset=utf-8";
                case ".js":
                case ".mjs":
                    return "application/javascript; charset=utf-8";
                case ".json":
                    return "application/json; charset=utf-8";
                case ".css":
                    return "text/css; charset=utf-8";
                case ".png":
                    return "image/png";
                case ".jpg":
                case ".jpeg":
                    return "image/jpeg";
                case ".svg":
                    return "image/svg+xml";
                case ".ico":
                    return "image/x-icon";
                case ".woff":
                    return "font/woff";
                case ".woff2":
                    return "font/woff2";
                case ".ttf":
                    return "font/ttf";
                case ".otf":
                    return "font/otf";
                case ".wasm":
                    return "application/wasm";
                case ".map":
                    return "application/json; charset=utf-8";
                default:
                    return "application/octet-stream";
            }
        }
    }
}
