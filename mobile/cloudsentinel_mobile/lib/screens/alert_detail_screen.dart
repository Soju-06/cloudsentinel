import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../api.dart';
import '../theme.dart';

class AlertDetailScreen extends StatefulWidget {
  const AlertDetailScreen({
    super.key,
    required this.alert,
    required this.host,
    required this.api,
    this.onChanged,
  });

  final AlertItem alert;
  final String host;
  final ApiClient api;
  final VoidCallback? onChanged;

  @override
  State<AlertDetailScreen> createState() => _AlertDetailScreenState();
}

class _AlertDetailScreenState extends State<AlertDetailScreen> {
  late AlertItem _alert;
  bool _busy = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _alert = widget.alert;
  }

  String get _statusLabel => _alert.status.toUpperCase();

  Future<void> _apply({
    String? status,
    String? assignee,
    bool updateAssignee = false,
  }) async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final updated = await widget.api.updateTriage(
        _alert.id,
        status: status,
        assignee: assignee,
        updateAssignee: updateAssignee,
      );
      if (!mounted) return;
      setState(() => _alert = updated);
      widget.onChanged?.call();
      final owner = updated.assignee == null ? '' : ' · ${updated.assignee}';
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Alert #${updated.id} is now '
            '${updated.status}$owner')),
      );
    } catch (error) {
      if (!mounted) return;
      setState(() => _error = describeError(error));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _assign() async {
    final controller = TextEditingController(text: _alert.assignee ?? '');
    final result = await showDialog<String>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        backgroundColor: AppColors.panel,
        title: const Text(
          'ASSIGN ALERT',
          style: TextStyle(fontSize: 14, letterSpacing: 1.6),
        ),
        content: TextField(
          controller: controller,
          autofocus: true,
          decoration: const InputDecoration(hintText: 'analyst@example.com'),
          onSubmitted: (value) => Navigator.of(dialogContext).pop(value),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(),
            child: const Text('CANCEL'),
          ),
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(''),
            child: const Text('CLEAR'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(dialogContext).pop(controller.text),
            child: const Text('ASSIGN'),
          ),
        ],
      ),
    );
    final value = result?.trim();
    controller.dispose();
    if (result == null) return;
    await _apply(
      assignee: (value == null || value.isEmpty) ? null : value,
      updateAssignee: true,
    );
  }

  Widget _action(String label, VoidCallback onPressed) {
    return OutlinedButton(
      onPressed: _busy ? null : onPressed,
      style: OutlinedButton.styleFrom(
        foregroundColor: AppColors.cyan,
        side: const BorderSide(color: AppColors.line),
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
        textStyle: const TextStyle(
          fontSize: 10.5,
          fontWeight: FontWeight.w700,
          letterSpacing: 1.1,
        ),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
      ),
      child: Text(label),
    );
  }

  @override
  Widget build(BuildContext context) {
    final color = AppColors.forSeverity(_alert.severity);
    return Scaffold(
      appBar: AppBar(
        title: const Text('ALERT DETAIL'),
        actions: [
          IconButton(
            tooltip: 'Copy alert as JSON',
            onPressed: () => _copy(context),
            icon: const Icon(Icons.copy_all_outlined, size: 20),
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.fromLTRB(16, 8, 16, 32),
        children: [
          GlassPanel(
            borderColor: color.withValues(alpha: 0.4),
            gradient: LinearGradient(
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
              colors: [color.withValues(alpha: 0.12), AppColors.panel],
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    _Badge(label: _alert.severity.toUpperCase(), color: color),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        (detectorLabels[_alert.detector] ?? _alert.detector)
                            .toUpperCase(),
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(
                          color: AppColors.muted,
                          fontSize: 9.5,
                          letterSpacing: 1.4,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                    ),
                    Text(
                      '#${_alert.id}',
                      style: const TextStyle(
                        color: AppColors.muted,
                        fontSize: 10,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 12),
                Text(
                  _alert.title,
                  style: const TextStyle(
                    color: AppColors.text,
                    fontSize: 18,
                    fontWeight: FontWeight.w800,
                    height: 1.3,
                  ),
                ),
                if (_alert.description.isNotEmpty) ...[
                  const SizedBox(height: 10),
                  Text(
                    _alert.description,
                    style: const TextStyle(
                      color: AppColors.muted,
                      fontSize: 12,
                      height: 1.6,
                    ),
                  ),
                ],
              ],
            ),
          ),
          const SizedBox(height: 12),
          _Section(
            title: 'TRIAGE',
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    _Badge(
                      label: _statusLabel,
                      color: AppColors.forStatus(_alert.status),
                    ),
                    const SizedBox(width: 10),
                    const Icon(
                      Icons.person_outline,
                      size: 14,
                      color: AppColors.muted,
                    ),
                    const SizedBox(width: 5),
                    Expanded(
                      child: Text(
                        _alert.assignee ?? 'Unassigned',
                        overflow: TextOverflow.ellipsis,
                        style: TextStyle(
                          color: _alert.assignee == null
                              ? AppColors.muted
                              : AppColors.text,
                          fontSize: 11.5,
                        ),
                      ),
                    ),
                  ],
                ),
                if (_error != null) ...[
                  const SizedBox(height: 10),
                  Text(
                    _error!,
                    style: const TextStyle(
                      color: AppColors.critical,
                      fontSize: 11,
                    ),
                  ),
                ],
                const SizedBox(height: 12),
                Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  crossAxisAlignment: WrapCrossAlignment.center,
                  children: [
                    if (_alert.status == 'open')
                      _action(
                        'ACKNOWLEDGE',
                        () => _apply(status: 'acknowledged'),
                      ),
                    if (_alert.status != 'closed')
                      _action('CLOSE', () => _apply(status: 'closed')),
                    if (_alert.status == 'closed')
                      _action('REOPEN', () => _apply(status: 'open')),
                    _action('ASSIGN', _assign),
                    if (_busy)
                      const SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      ),
                  ],
                ),
              ],
            ),
          ),
          const SizedBox(height: 12),
          _Section(
            title: 'ENTITY',
            child: Row(
              children: [
                const Icon(Icons.hub_outlined, color: AppColors.cyan, size: 16),
                const SizedBox(width: 8),
                Expanded(
                  child: SelectableText(
                    _alert.entity,
                    style: const TextStyle(
                      color: AppColors.cyan,
                      fontSize: 13,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ),
                if (_alert.entityType.isNotEmpty)
                  Text(
                    _alert.entityType.toUpperCase(),
                    style: const TextStyle(
                      color: AppColors.muted,
                      fontSize: 9,
                      letterSpacing: 1,
                    ),
                  ),
              ],
            ),
          ),
          const SizedBox(height: 12),
          _Section(
            title: 'TIMELINE',
            child: Column(
              children: [
                _KeyValue(
                  label: 'FIRST SEEN',
                  value: absoluteTime(_alert.firstSeen),
                ),
                const SizedBox(height: 8),
                _KeyValue(
                  label: 'LAST SEEN',
                  value: absoluteTime(_alert.lastSeen),
                ),
                const SizedBox(height: 8),
                _KeyValue(
                  label: 'RELATIVE',
                  value: relativeTime(_alert.lastSeen),
                ),
              ],
            ),
          ),
          const SizedBox(height: 12),
          _Section(
            title: 'IMPACT',
            child: Row(
              children: [
                Expanded(
                  child: _Stat(
                    label: 'EVENTS',
                    value: '${_alert.eventCount}',
                    color: AppColors.high,
                  ),
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: _Stat(
                    label: 'SOURCE',
                    value: widget.host,
                    color: AppColors.violet,
                    small: true,
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 12),
          _Section(
            title: 'EVIDENCE',
            child: _alert.evidence.isEmpty
                ? const Text(
                    'No structured evidence returned by the server.',
                    style: TextStyle(color: AppColors.muted, fontSize: 11),
                  )
                : Column(
                    children: _alert.evidence.entries
                        .map(
                          (entry) => _EvidenceRow(
                            label: entry.key,
                            value: _stringify(entry.value),
                          ),
                        )
                        .toList(growable: false),
                  ),
          ),
          const SizedBox(height: 12),
          _Section(
            title: 'FINGERPRINT',
            child: SelectableText(
              _alert.fingerprint,
              style: const TextStyle(
                color: AppColors.muted,
                fontSize: 10.5,
                height: 1.5,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Future<void> _copy(BuildContext context) async {
    final payload = const JsonEncoder.withIndent('  ').convert({
      'id': _alert.id,
      'fingerprint': _alert.fingerprint,
      'detector': _alert.detector,
      'severity': _alert.severity,
      'status': _alert.status,
      'assignee': _alert.assignee,
      'triaged_at': _alert.triagedAt?.toIso8601String(),
      'title': _alert.title,
      'description': _alert.description,
      'entity': _alert.entity,
      'entity_type': _alert.entityType,
      'event_count': _alert.eventCount,
      'first_seen': _alert.firstSeen?.toIso8601String(),
      'last_seen': _alert.lastSeen?.toIso8601String(),
      'evidence': _alert.evidence,
    });
    await Clipboard.setData(ClipboardData(text: payload));
    if (!context.mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Alert JSON copied to clipboard')),
    );
  }

  static String _stringify(Object? value) {
    if (value == null) return 'null';
    if (value is String) return value;
    if (value is num || value is bool) return '$value';
    if (value is List) {
      return value.map(_stringify).join(', ');
    }
    if (value is Map) {
      return const JsonEncoder.withIndent('  ').convert(value);
    }
    return '$value';
  }
}

class _Section extends StatelessWidget {
  const _Section({required this.title, required this.child});

  final String title;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    return GlassPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title,
            style: const TextStyle(
              color: AppColors.muted,
              fontSize: 9.5,
              letterSpacing: 2,
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 12),
          child,
        ],
      ),
    );
  }
}

class _Badge extends StatelessWidget {
  const _Badge({required this.label, required this.color});

  final String label;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.14),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: color.withValues(alpha: 0.6)),
      ),
      child: Text(
        label,
        style: TextStyle(
          color: color,
          fontSize: 8.5,
          fontWeight: FontWeight.w800,
          letterSpacing: 1,
        ),
      ),
    );
  }
}

class _KeyValue extends StatelessWidget {
  const _KeyValue({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          width: 92,
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

class _Stat extends StatelessWidget {
  const _Stat({
    required this.label,
    required this.value,
    required this.color,
    this.small = false,
  });

  final String label;
  final String value;
  final Color color;
  final bool small;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: color.withValues(alpha: 0.3)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            label,
            style: TextStyle(
              color: color,
              fontSize: 8.5,
              letterSpacing: 1.4,
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 5),
          Text(
            value,
            maxLines: 2,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              color: AppColors.text,
              fontSize: small ? 11 : 20,
              height: 1.2,
              fontWeight: FontWeight.w800,
            ),
          ),
        ],
      ),
    );
  }
}

class _EvidenceRow extends StatelessWidget {
  const _EvidenceRow({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 110,
            child: Text(
              label,
              style: const TextStyle(
                color: AppColors.muted,
                fontSize: 10,
                height: 1.5,
              ),
            ),
          ),
          Expanded(
            child: SelectableText(
              value,
              style: const TextStyle(
                color: AppColors.cyan,
                fontSize: 10.5,
                height: 1.5,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
