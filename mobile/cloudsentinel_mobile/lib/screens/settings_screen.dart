import 'package:flutter/material.dart';

import '../api.dart';
import '../connection.dart';
import '../theme.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({
    super.key,
    required this.connection,
    required this.onDisconnect,
  });

  final Connection connection;
  final Future<void> Function() onDisconnect;

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  bool _checking = false;
  String? _status;
  bool _healthy = false;

  Future<void> _checkHealth() async {
    setState(() {
      _checking = true;
      _status = null;
    });
    try {
      final health = await widget.connection.client.health();
      if (!mounted) return;
      setState(() {
        _healthy = health['status'] == 'ok';
        _status =
            'OK · API ${health['version'] ?? '?'} · '
            '${health['alerts'] ?? 0} alerts stored';
      });
    } catch (error) {
      if (!mounted) return;
      setState(() {
        _healthy = false;
        _status = describeError(error);
      });
    } finally {
      if (mounted) setState(() => _checking = false);
    }
  }

  Future<void> _confirmDisconnect() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        backgroundColor: AppColors.panel,
        title: const Text(
          'DISCONNECT',
          style: TextStyle(
            color: AppColors.text,
            fontSize: 14,
            letterSpacing: 1.6,
          ),
        ),
        content: const Text(
          'The saved server URL and token will be removed from this device.',
          style: TextStyle(color: AppColors.muted, fontSize: 12, height: 1.5),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(false),
            child: const Text('CANCEL'),
          ),
          FilledButton(
            style: FilledButton.styleFrom(
              backgroundColor: AppColors.critical,
              minimumSize: const Size(96, 42),
            ),
            onPressed: () => Navigator.of(dialogContext).pop(true),
            child: const Text('DISCONNECT'),
          ),
        ],
      ),
    );
    if (confirmed == true) {
      await widget.onDisconnect();
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('SETTINGS')),
      body: ListView(
        padding: const EdgeInsets.fromLTRB(16, 8, 16, 32),
        children: [
          GlassPanel(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const _Label('CONNECTION'),
                const SizedBox(height: 14),
                _Row(label: 'SERVER', value: widget.connection.baseUrl),
                const SizedBox(height: 10),
                _Row(label: 'HOST', value: widget.connection.host),
                const SizedBox(height: 10),
                _Row(
                  label: 'TOKEN',
                  value: widget.connection.token.isEmpty
                      ? 'not set (open server)'
                      : '••••••••${_tail(widget.connection.token)}',
                ),
              ],
            ),
          ),
          const SizedBox(height: 12),
          GlassPanel(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const _Label('DIAGNOSTICS'),
                const SizedBox(height: 12),
                const Text(
                  'Ping the server to confirm it is reachable and the stored '
                  'token is still valid.',
                  style: TextStyle(
                    color: AppColors.muted,
                    fontSize: 11.5,
                    height: 1.5,
                  ),
                ),
                if (_status != null) ...[
                  const SizedBox(height: 12),
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 12,
                      vertical: 10,
                    ),
                    decoration: BoxDecoration(
                      color: (_healthy ? AppColors.low : AppColors.critical)
                          .withValues(alpha: 0.1),
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(
                        color: (_healthy ? AppColors.low : AppColors.critical)
                            .withValues(alpha: 0.45),
                      ),
                    ),
                    child: Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Icon(
                          _healthy
                              ? Icons.check_circle_outline
                              : Icons.error_outline,
                          size: 16,
                          color: _healthy ? AppColors.low : AppColors.critical,
                        ),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            _status!,
                            style: TextStyle(
                              color: _healthy
                                  ? AppColors.low
                                  : AppColors.critical,
                              fontSize: 11,
                              height: 1.4,
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
                const SizedBox(height: 14),
                FilledButton.icon(
                  onPressed: _checking ? null : _checkHealth,
                  icon: _checking
                      ? const SizedBox(
                          width: 16,
                          height: 16,
                          child: CircularProgressIndicator(
                            strokeWidth: 2,
                            color: AppColors.background,
                          ),
                        )
                      : const Icon(Icons.network_check, size: 18),
                  label: Text(_checking ? 'CHECKING…' : 'TEST CONNECTION'),
                ),
              ],
            ),
          ),
          const SizedBox(height: 12),
          GlassPanel(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const _Label('ABOUT'),
                const SizedBox(height: 12),
                const _Row(label: 'APP', value: 'CloudSentinel Mobile 1.0.0'),
                const SizedBox(height: 10),
                const _Row(label: 'CLIENT', value: 'Flutter · Android'),
                const SizedBox(height: 10),
                const _Row(
                  label: 'MODE',
                  value: 'Read-only console (scan optional)',
                ),
              ],
            ),
          ),
          const SizedBox(height: 12),
          GlassPanel(
            borderColor: AppColors.critical.withValues(alpha: 0.4),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const _Label('SESSION'),
                const SizedBox(height: 12),
                const Text(
                  'Disconnecting removes the saved URL and token. You can '
                  'reconnect at any time.',
                  style: TextStyle(
                    color: AppColors.muted,
                    fontSize: 11.5,
                    height: 1.5,
                  ),
                ),
                const SizedBox(height: 14),
                OutlinedButton.icon(
                  style: OutlinedButton.styleFrom(
                    foregroundColor: AppColors.critical,
                    side: BorderSide(
                      color: AppColors.critical.withValues(alpha: 0.6),
                    ),
                    minimumSize: const Size.fromHeight(46),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(12),
                    ),
                  ),
                  onPressed: _confirmDisconnect,
                  icon: const Icon(Icons.link_off, size: 18),
                  label: const Text('DISCONNECT'),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  static String _tail(String token) =>
      token.length <= 4 ? '' : token.substring(token.length - 4);
}

class _Label extends StatelessWidget {
  const _Label(this.text);

  final String text;

  @override
  Widget build(BuildContext context) {
    return Text(
      text,
      style: const TextStyle(
        color: AppColors.muted,
        fontSize: 9.5,
        letterSpacing: 2,
        fontWeight: FontWeight.w700,
      ),
    );
  }
}

class _Row extends StatelessWidget {
  const _Row({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          width: 74,
          child: Text(
            label,
            style: const TextStyle(
              color: AppColors.muted,
              fontSize: 9,
              letterSpacing: 1.2,
              fontWeight: FontWeight.w700,
            ),
          ),
        ),
        Expanded(
          child: SelectableText(
            value,
            style: const TextStyle(
              color: AppColors.text,
              fontSize: 11.5,
              height: 1.4,
            ),
          ),
        ),
      ],
    );
  }
}
