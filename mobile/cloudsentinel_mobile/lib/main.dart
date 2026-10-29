import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'api.dart';
import 'connection.dart';
import 'screens/connect_screen.dart';
import 'screens/dashboard_screen.dart';
import 'theme.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const CloudSentinelApp());
}

class CloudSentinelApp extends StatefulWidget {
  const CloudSentinelApp({super.key});

  @override
  State<CloudSentinelApp> createState() => _CloudSentinelAppState();
}

class _CloudSentinelAppState extends State<CloudSentinelApp> {
  static const _urlKey = 'server_url';
  static const _tokenKey = 'api_token';

  Connection? _connection;
  String? _presetUrl;
  String _presetToken = '';
  bool _ready = false;

  @override
  void initState() {
    super.initState();
    _restore();
  }

  Future<void> _restore() async {
    final prefs = await SharedPreferences.getInstance();
    String? url = prefs.getString(_urlKey);
    String token = prefs.getString(_tokenKey) ?? '';

    // The Windows shell can hand over a server/token pair on the command line
    // (CloudSentinel.exe --server ... --token ...) via query parameters.
    if (kIsWeb) {
      final query = Uri.base.queryParameters;
      final server = query['server']?.trim();
      if (server != null && server.isNotEmpty) {
        url = ApiClient.normalizeBaseUrl(server);
        token = query['token'] ?? '';
        await prefs.setString(_urlKey, url);
        await prefs.setString(_tokenKey, token);
      }
    }

    if (!mounted) return;
    setState(() {
      _connection = (url == null || url.isEmpty)
          ? null
          : Connection(baseUrl: url, token: token);
      _ready = true;
    });
  }

  Future<void> _connect(Connection connection) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_urlKey, connection.baseUrl);
    await prefs.setString(_tokenKey, connection.token);
    if (!mounted) return;
    setState(() {
      _connection = connection;
      _presetUrl = null;
      _presetToken = '';
    });
  }

  /// Returns to the connect screen with the failed address pre-filled, so the
  /// user can point the app at a server that is actually running.
  Future<void> _changeServer() async {
    final current = _connection;
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_urlKey);
    await prefs.remove(_tokenKey);
    if (!mounted) return;
    setState(() {
      _presetUrl = current?.baseUrl;
      _presetToken = current?.token ?? '';
      _connection = null;
    });
  }

  Future<void> _disconnect() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_urlKey);
    await prefs.remove(_tokenKey);
    if (!mounted) return;
    setState(() => _connection = null);
  }

  @override
  Widget build(BuildContext context) {
    final connection = _connection;
    return MaterialApp(
      title: 'CloudSentinel',
      debugShowCheckedModeBanner: false,
      theme: buildTheme(),
      home: AnimatedSwitcher(
        duration: const Duration(milliseconds: 350),
        child: !_ready
            ? const _SplashScreen()
            : connection == null
            ? ConnectScreen(
                onConnected: _connect,
                initialUrl: _presetUrl,
                initialToken: _presetToken.isEmpty ? null : _presetToken,
              )
            : DashboardScreen(
                key: ValueKey(connection.baseUrl),
                connection: connection,
                onDisconnect: _disconnect,
                onChangeServer: _changeServer,
              ),
      ),
    );
  }
}

class _SplashScreen extends StatelessWidget {
  const _SplashScreen();

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              Icons.shield_moon_outlined,
              size: 72,
              color: AppColors.cyan,
              shadows: [
                Shadow(
                  color: AppColors.cyan.withValues(alpha: 0.55),
                  blurRadius: 28,
                ),
              ],
            ),
            const SizedBox(height: 18),
            const Text(
              'CLOUDSENTINEL',
              style: TextStyle(
                color: AppColors.cyan,
                fontSize: 18,
                fontWeight: FontWeight.w800,
                letterSpacing: 4,
              ),
            ),
            const SizedBox(height: 28),
            const SizedBox(
              width: 26,
              height: 26,
              child: CircularProgressIndicator(strokeWidth: 2),
            ),
          ],
        ),
      ),
    );
  }
}
