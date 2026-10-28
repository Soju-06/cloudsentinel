import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter/material.dart';

import '../api.dart';
import '../connection.dart';
import '../theme.dart';

class ConnectScreen extends StatefulWidget {
  const ConnectScreen({super.key, required this.onConnected});

  final Future<void> Function(Connection connection) onConnected;

  @override
  State<ConnectScreen> createState() => _ConnectScreenState();
}

class _ConnectScreenState extends State<ConnectScreen> {
  final _urlController = TextEditingController(
    text: kIsWeb ? 'http://127.0.0.1:8080' : 'http://192.168.1.10:8080',
  );
  final _tokenController = TextEditingController();

  bool _busy = false;
  bool _obscureToken = true;
  String? _error;

  @override
  void dispose() {
    _urlController.dispose();
    _tokenController.dispose();
    super.dispose();
  }

  Future<void> _connect() async {
    final baseUrl = ApiClient.normalizeBaseUrl(_urlController.text);
    if (baseUrl.isEmpty) {
      setState(() => _error = 'Enter the CloudSentinel server URL.');
      return;
    }

    setState(() {
      _busy = true;
      _error = null;
    });

    final client = ApiClient(baseUrl: baseUrl, token: _tokenController.text);
    try {
      final health = await client.health();
      if (health['status'] != 'ok') {
        throw ApiException('Server reported an unhealthy state');
      }
      // Verifies the token before we persist the connection.
      await client.fetchSummary();
      await widget.onConnected(
        Connection(baseUrl: baseUrl, token: _tokenController.text.trim()),
      );
    } catch (error) {
      if (!mounted) return;
      setState(() => _error = describeError(error));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
            colors: [Color(0xFF050810), Color(0xFF0A1224), Color(0xFF120B2A)],
          ),
        ),
        child: SafeArea(
          child: Center(
            child: SingleChildScrollView(
              padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 32),
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 460),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    _buildBrand(),
                    const SizedBox(height: 30),
                    GlassPanel(
                      padding: const EdgeInsets.fromLTRB(20, 22, 20, 22),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          const Text(
                            'CONNECT TO YOUR SERVER',
                            style: TextStyle(
                              color: AppColors.text,
                              fontSize: 13,
                              fontWeight: FontWeight.w700,
                              letterSpacing: 1.6,
                            ),
                          ),
                          const SizedBox(height: 6),
                          const Text(
                            'This console reads alerts from the CloudSentinel API running on your computer or server.',
                            style: TextStyle(
                              color: AppColors.muted,
                              fontSize: 12,
                              height: 1.5,
                            ),
                          ),
                          const SizedBox(height: 20),
                          TextField(
                            controller: _urlController,
                            keyboardType: TextInputType.url,
                            textInputAction: TextInputAction.next,
                            autocorrect: false,
                            decoration: const InputDecoration(
                              labelText: 'SERVER URL',
                              hintText: 'http://127.0.0.1:8080',
                              prefixIcon: Icon(
                                Icons.dns_outlined,
                                color: AppColors.muted,
                                size: 20,
                              ),
                            ),
                          ),
                          const SizedBox(height: 12),
                          TextField(
                            controller: _tokenController,
                            obscureText: _obscureToken,
                            textInputAction: TextInputAction.done,
                            onSubmitted: (_) => _busy ? null : _connect(),
                            decoration: InputDecoration(
                              labelText: 'API TOKEN (OPTIONAL)',
                              hintText: 'X-API-Token value',
                              prefixIcon: const Icon(
                                Icons.key_outlined,
                                color: AppColors.muted,
                                size: 20,
                              ),
                              suffixIcon: IconButton(
                                tooltip: _obscureToken ? 'Show token' : 'Hide token',
                                icon: Icon(
                                  _obscureToken
                                      ? Icons.visibility_outlined
                                      : Icons.visibility_off_outlined,
                                  color: AppColors.muted,
                                  size: 20,
                                ),
                                onPressed: () => setState(
                                  () => _obscureToken = !_obscureToken,
                                ),
                              ),
                            ),
                          ),
                          if (_error != null) ...[
                            const SizedBox(height: 14),
                            _ErrorBox(message: _error!),
                          ],
                          const SizedBox(height: 18),
                          FilledButton.icon(
                            onPressed: _busy ? null : _connect,
                            icon: _busy
                                ? const SizedBox(
                                    width: 16,
                                    height: 16,
                                    child: CircularProgressIndicator(
                                      strokeWidth: 2,
                                      color: AppColors.background,
                                    ),
                                  )
                                : const Icon(Icons.bolt, size: 20),
                            label: Text(_busy ? 'CONNECTING…' : 'CONNECT'),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 22),
                    const _ServerHint(),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildBrand() {
    return Column(
      children: [
        Container(
          padding: const EdgeInsets.all(18),
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            border: Border.all(color: AppColors.line),
            boxShadow: [
              BoxShadow(
                color: AppColors.cyan.withValues(alpha: 0.18),
                blurRadius: 40,
                spreadRadius: 2,
              ),
            ],
          ),
          child: const Icon(
            Icons.shield_moon_outlined,
            color: AppColors.cyan,
            size: 46,
          ),
        ),
        const SizedBox(height: 16),
        const Text(
          'CLOUDSENTINEL',
          textAlign: TextAlign.center,
          style: TextStyle(
            color: AppColors.cyan,
            fontSize: 24,
            fontWeight: FontWeight.w800,
            letterSpacing: 5,
          ),
        ),
        const SizedBox(height: 6),
        const Text(
          'SECURITY OPERATIONS CONSOLE',
          textAlign: TextAlign.center,
          style: TextStyle(
            color: AppColors.muted,
            fontSize: 10,
            letterSpacing: 3,
          ),
        ),
      ],
    );
  }
}

class _ErrorBox extends StatelessWidget {
  const _ErrorBox({required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: AppColors.critical.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: AppColors.critical.withValues(alpha: 0.5)),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Icon(Icons.error_outline, color: AppColors.critical, size: 18),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              message,
              style: const TextStyle(
                color: AppColors.critical,
                fontSize: 11.5,
                height: 1.4,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _ServerHint extends StatelessWidget {
  const _ServerHint();

  @override
  Widget build(BuildContext context) {
    return GlassPanel(
      padding: const EdgeInsets.all(14),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: const [
              Icon(Icons.terminal, color: AppColors.violet, size: 16),
              SizedBox(width: 8),
              Text(
                'START THE API',
                style: TextStyle(
                  color: AppColors.muted,
                  fontSize: 10,
                  letterSpacing: 1.8,
                  fontWeight: FontWeight.w700,
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          const SelectableText(
            'python -m cloudsentinel serve --port 8080 --token YOUR_TOKEN',
            style: TextStyle(
              color: AppColors.text,
              fontSize: 10.5,
              height: 1.6,
            ),
          ),
          const SizedBox(height: 8),
          const Text(
            'Android: add --host 0.0.0.0 and use the computer\'s LAN address. '
            'Windows: http://127.0.0.1:8080 works locally.',
            style: TextStyle(color: AppColors.muted, fontSize: 10.5, height: 1.5),
          ),
        ],
      ),
    );
  }
}
