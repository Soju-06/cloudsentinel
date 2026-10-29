import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../api.dart';
import '../theme.dart';

class AlertDetailScreen extends StatelessWidget {
  const AlertDetailScreen({super.key, required this.alert, required this.host});

  final AlertItem alert;
  final String host;

  @override
  Widget build(BuildContext context) {
    final color = AppColors.forSeverity(alert.severity);
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
                    _Badge(label: alert.severity.toUpperCase(), color: color),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        (detectorLabels[alert.detector] ?? alert.detector)
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
                      '#${alert.id}',
                      style: const TextStyle(
                        color: AppColors.muted,
                        fontSize: 10,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 12),
                Text(
                  alert.title,
                  style: const TextStyle(
                    color: AppColors.text,
                    fontSize: 18,
                    fontWeight: FontWeight.w800,
                    height: 1.3,
                  ),
                ),
                if (alert.description.isNotEmpty) ...[
                  const SizedBox(height: 10),
                  Text(
                    alert.description,
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
          const SizedBox(height: 14),
          _Section(
            title: 'ENTITY',
            child: Row(
              children: [
                const Icon(Icons.hub_outlined, color: AppColors.cyan, size: 16),
                const SizedBox(width: 8),
                Expanded(
                  child: SelectableText(
                    alert.entity,
                    style: const TextStyle(
                      color: AppColors.cyan,
                      fontSize: 13,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ),
                if (alert.entityType.isNotEmpty)
                  Text(
                    alert.entityType.toUpperCase(),
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
                  value: absoluteTime(alert.firstSeen),
                ),
                const SizedBox(height: 8),
                _KeyValue(
                  label: 'LAST SEEN',
                  value: absoluteTime(alert.lastSeen),
                ),
                const SizedBox(height: 8),
                _KeyValue(
                  label: 'RELATIVE',
                  value: relativeTime(alert.lastSeen),
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
                    value: '${alert.eventCount}',
                    color: AppColors.high,
                  ),
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: _Stat(
                    label: 'SOURCE',
                    value: host,
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
            child: alert.evidence.isEmpty
                ? const Text(
                    'No structured evidence returned by the server.',
                    style: TextStyle(color: AppColors.muted, fontSize: 11),
                  )
                : Column(
                    children: alert.evidence.entries
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
              alert.fingerprint,
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
      'id': alert.id,
      'fingerprint': alert.fingerprint,
      'detector': alert.detector,
      'severity': alert.severity,
      'title': alert.title,
      'description': alert.description,
      'entity': alert.entity,
      'entity_type': alert.entityType,
      'event_count': alert.eventCount,
      'first_seen': alert.firstSeen?.toIso8601String(),
      'last_seen': alert.lastSeen?.toIso8601String(),
      'evidence': alert.evidence,
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
