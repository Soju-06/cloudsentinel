/// Builds the shell command that starts the CloudSentinel API for a client.
///
/// The connection-error screen shows the result so a user who forgot to start
/// the server can copy one line instead of guessing the flags.
String serveCommandFor(
  String baseUrl, {
  bool lan = false,
  String token = 'YOUR_TOKEN',
}) {
  final uri = Uri.tryParse(baseUrl.trim());
  final parts = <String>['python -m cloudsentinel serve'];

  // A phone reaches the computer over Wi-Fi, so the API must listen on all
  // interfaces. The desktop client talks to loopback and needs no flag.
  if (lan) {
    parts.add('--host 0.0.0.0');
  }
  if (uri != null && uri.hasPort) {
    parts.add('--port ${uri.port}');
  }
  if (token.isNotEmpty) {
    parts.add('--token $token');
  }

  return parts.join(' ');
}
