import 'package:flutter/foundation.dart'
    show TargetPlatform, defaultTargetPlatform, kIsWeb;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show Clipboard, ClipboardData;

import '../api.dart';
import '../connection.dart';
import '../serve_command.dart';
import '../theme.dart';
import '../widgets/golf_attempt.dart';
import 'alert_detail_screen.dart';
import 'settings_screen.dart';

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({
    super.key,
    required this.connection,
    required this.onDisconnect,
    required this.onChangeServer,
  });

  final Connection connection;
  final Future<void> Function() onDisconnect;
  final Future<void> Function() onChangeServer;

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  late final ApiClient _api = widget.connection.client;
  final _searchController = TextEditingController();

  SummaryData? _summary;
  List<AlertItem> _alerts = const [];
  int _total = 0;
  bool _loading = true;
  bool _scanning = false;
  String? _error;
  String? _severity;
  String? _detector;
  String _search = '';
  DateTime? _updatedAt;
  int _request = 0;

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  Future<void> _load({bool silent = false}) async {
    final request = ++_request;
    if (!silent || _summary == null) {
      setState(() {
        _loading = true;
        _error = null;
      });
    } else {
      setState(() => _error = null);
    }

    try {
      final summary = await _api.fetchSummary();
      final page = await _api.fetchAlerts(
        severity: _severity,
        detector: _detector,
        search: _search,
        limit: 200,
      );
      if (!mounted || request != _request) return;
      setState(() {
        _summary = summary;
        _alerts = page.alerts;
        _total = page.total;
        _updatedAt = DateTime.now();
        _loading = false;
      });
    } catch (error) {
      if (!mounted || request != _request) return;
      setState(() {
        _error = describeError(error);
        _loading = false;
      });
    }
  }

  void _setSeverity(String? value) {
    if (_severity == value) return;
    setState(() => _severity = value);
    _load(silent: true);
  }

  void _setDetector(String? value) {
    if (_detector == value) return;
    setState(() => _detector = value);
    _load(silent: true);
  }

  void _submitSearch(String value) {
    if (_search == value.trim()) return;
    setState(() => _search = value.trim());
    _load(silent: true);
  }

  Future<void> _clearSearch() async {
    _searchController.clear();
    if (_search.isEmpty) return;
    setState(() => _search = '');
    await _load(silent: true);
  }

  Future<void> _openSettings() async {
    await Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (_) => SettingsScreen(
          connection: widget.connection,
          onDisconnect: () async {
            Navigator.of(context).pop();
            await widget.onDisconnect();
          },
        ),
      ),
    );
    if (mounted) _load(silent: true);
  }

  Future<void> _runScan() async {
    setState(() => _scanning = true);
    try {
      final result = await _api.scan();
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            'Scan complete — ${result['events_scanned']} events, '
            '${result['alerts']} alerts',
          ),
        ),
      );
      await _load(silent: true);
    } catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text(describeError(error))));
    } finally {
      if (mounted) setState(() => _scanning = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final summary = _summary;
    return Scaffold(
      appBar: AppBar(
        title: const Text('CLOUDSENTINEL'),
        actions: [
          IconButton(
            tooltip: 'Refresh',
            onPressed: _loading ? null : () => _load(silent: true),
            icon: const Icon(Icons.refresh, size: 22),
          ),
          IconButton(
            tooltip: 'Settings',
            onPressed: _openSettings,
            icon: const Icon(Icons.settings_outlined, size: 22),
          ),
        ],
      ),
      floatingActionButton: summary?.scanEnabled == true
          ? FloatingActionButton.extended(
              onPressed: _scanning ? null : _runScan,
              backgroundColor: AppColors.cyan,
              foregroundColor: AppColors.background,
              icon: _scanning
                  ? const SizedBox(
                      width: 18,
                      height: 18,
                      child: CircularProgressIndicator(
                        strokeWidth: 2,
                        color: AppColors.background,
                      ),
                    )
                  : const Icon(Icons.radar, size: 20),
              label: Text(_scanning ? 'SCANNING…' : 'SCAN'),
            )
          : null,
      body: _buildBody(),
    );
  }

  Widget _buildBody() {
    if (_loading && _summary == null) {
      return const Center(child: CircularProgressIndicator());
    }
    if (_summary == null) {
      return ConnectionLostView(
        message: _error ?? 'Unable to load',
        serverUrl: widget.connection.baseUrl,
        onRetry: _load,
        onChangeServer: widget.onChangeServer,
      );
    }

    final summary = _summary!;
    return RefreshIndicator(
      onRefresh: () => _load(silent: true),
      child: ListView(
        physics: const AlwaysScrollableScrollPhysics(),
        padding: const EdgeInsets.fromLTRB(16, 8, 16, 96),
        children: [
          _ConnectionPill(
            host: widget.connection.host,
            updatedAt: _updatedAt,
            warning: _error,
          ),
          const SizedBox(height: 16),
          Row(
            children: [
              Expanded(
                child: _MetricCard(
                  label: 'TOTAL',
                  value: '${summary.totalAlerts}',
                  color: AppColors.cyan,
                  icon: Icons.notifications_active_outlined,
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: _MetricCard(
                  label: 'CRITICAL',
                  value: '${summary.count('critical')}',
                  color: AppColors.critical,
                  icon: Icons.dangerous_outlined,
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          Row(
            children: [
              Expanded(
                child: _MetricCard(
                  label: 'HIGH',
                  value: '${summary.count('high')}',
                  color: AppColors.high,
                  icon: Icons.warning_amber_outlined,
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: _MetricCard(
                  label: 'ENTITIES',
                  value: '${summary.affectedEntities}',
                  color: AppColors.violet,
                  icon: Icons.hub_outlined,
                ),
              ),
            ],
          ),
          const SizedBox(height: 20),
          _SectionLabel(
            label: 'SEVERITY',
            trailing: '$_total MATCH${_total == 1 ? '' : 'ES'}',
          ),
          const SizedBox(height: 8),
          _SeverityFilters(selected: _severity, onSelected: _setSeverity),
          const SizedBox(height: 14),
          _SectionLabel(label: 'DETECTOR'),
          const SizedBox(height: 8),
          _DetectorFilters(selected: _detector, onSelected: _setDetector),
          const SizedBox(height: 14),
          TextField(
            controller: _searchController,
            textInputAction: TextInputAction.search,
            onSubmitted: _submitSearch,
            decoration: InputDecoration(
              hintText: 'Search entity, title or detector…',
              isDense: true,
              prefixIcon: const Icon(
                Icons.search,
                color: AppColors.muted,
                size: 20,
              ),
              suffixIcon: _search.isEmpty
                  ? null
                  : IconButton(
                      tooltip: 'Clear search',
                      onPressed: _clearSearch,
                      icon: const Icon(
                        Icons.close,
                        color: AppColors.muted,
                        size: 18,
                      ),
                    ),
            ),
          ),
          const SizedBox(height: 18),
          _SectionLabel(label: 'ALERT FEED'),
          const SizedBox(height: 8),
          if (_alerts.isEmpty)
            const _EmptyState()
          else
            ..._alerts.map(
              (alert) => Padding(
                padding: const EdgeInsets.only(bottom: 10),
                child: _AlertCard(
                  alert: alert,
                  onTap: () => Navigator.of(context).push(
                    MaterialPageRoute<void>(
                      builder: (_) => AlertDetailScreen(
                        alert: alert,
                        host: widget.connection.host,
                      ),
                    ),
                  ),
                ),
              ),
            ),
          if (_total > _alerts.length)
            Padding(
              padding: const EdgeInsets.only(top: 4),
              child: Text(
                'Showing ${_alerts.length} of $_total alerts',
                textAlign: TextAlign.center,
                style: const TextStyle(color: AppColors.muted, fontSize: 10.5),
              ),
            ),
        ],
      ),
    );
  }
}

class _ConnectionPill extends StatelessWidget {
  const _ConnectionPill({
    required this.host,
    required this.updatedAt,
    this.warning,
  });

  final String host;
  final DateTime? updatedAt;
  final String? warning;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Row(
          children: [
            Container(
              width: 7,
              height: 7,
              decoration: BoxDecoration(
                color: warning == null ? AppColors.low : AppColors.high,
                shape: BoxShape.circle,
                boxShadow: [
                  BoxShadow(
                    color: (warning == null ? AppColors.low : AppColors.high)
                        .withValues(alpha: 0.7),
                    blurRadius: 8,
                  ),
                ],
              ),
            ),
            const SizedBox(width: 8),
            Expanded(
              child: Text(
                host,
                overflow: TextOverflow.ellipsis,
                style: const TextStyle(
                  color: AppColors.muted,
                  fontSize: 10.5,
                  letterSpacing: 0.6,
                ),
              ),
            ),
            Text(
              updatedAt == null ? 'SYNCING' : relativeTime(updatedAt),
              style: const TextStyle(
                color: AppColors.muted,
                fontSize: 10,
                letterSpacing: 0.8,
              ),
            ),
          ],
        ),
        if (warning != null) ...[
          const SizedBox(height: 8),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
            decoration: BoxDecoration(
              color: AppColors.high.withValues(alpha: 0.08),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: AppColors.high.withValues(alpha: 0.4)),
            ),
            child: Text(
              'Showing cached data — $warning',
              style: const TextStyle(color: AppColors.high, fontSize: 10.5),
            ),
          ),
        ],
      ],
    );
  }
}

class _MetricCard extends StatelessWidget {
  const _MetricCard({
    required this.label,
    required this.value,
    required this.color,
    required this.icon,
  });

  final String label;
  final String value;
  final Color color;
  final IconData icon;

  @override
  Widget build(BuildContext context) {
    return GlassPanel(
      padding: const EdgeInsets.fromLTRB(14, 12, 14, 14),
      borderColor: color.withValues(alpha: 0.28),
      gradient: LinearGradient(
        begin: Alignment.topLeft,
        end: Alignment.bottomRight,
        colors: [color.withValues(alpha: 0.1), AppColors.panel],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, color: color, size: 15),
              const SizedBox(width: 6),
              Text(
                label,
                style: TextStyle(
                  color: color.withValues(alpha: 0.9),
                  fontSize: 9.5,
                  letterSpacing: 1.6,
                  fontWeight: FontWeight.w700,
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            value,
            style: TextStyle(
              color: color,
              fontSize: 30,
              height: 1,
              fontWeight: FontWeight.w800,
            ),
          ),
        ],
      ),
    );
  }
}

class _SectionLabel extends StatelessWidget {
  const _SectionLabel({required this.label, this.trailing});

  final String label;
  final String? trailing;

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Text(
          label,
          style: const TextStyle(
            color: AppColors.muted,
            fontSize: 9.5,
            letterSpacing: 2,
            fontWeight: FontWeight.w700,
          ),
        ),
        const Spacer(),
        if (trailing != null)
          Text(
            trailing!,
            style: const TextStyle(
              color: AppColors.muted,
              fontSize: 9.5,
              letterSpacing: 1,
            ),
          ),
      ],
    );
  }
}

class _SeverityFilters extends StatelessWidget {
  const _SeverityFilters({required this.selected, required this.onSelected});

  final String? selected;
  final ValueChanged<String?> onSelected;

  @override
  Widget build(BuildContext context) {
    const values = ['critical', 'high', 'medium', 'low'];
    return SingleChildScrollView(
      scrollDirection: Axis.horizontal,
      child: Row(
        children: [
          _chip('ALL', null, AppColors.cyan),
          for (final value in values)
            _chip(value.toUpperCase(), value, AppColors.forSeverity(value)),
        ],
      ),
    );
  }

  Widget _chip(String label, String? value, Color color) {
    final active = selected == value;
    return Padding(
      padding: const EdgeInsets.only(right: 8),
      child: ChoiceChip(
        label: Text(
          label,
          style: TextStyle(
            color: active ? color : AppColors.muted,
            fontSize: 10,
            fontWeight: FontWeight.w700,
            letterSpacing: 0.8,
          ),
        ),
        selected: active,
        onSelected: (_) => onSelected(value),
        selectedColor: color.withValues(alpha: 0.14),
        side: BorderSide(
          color: active ? color.withValues(alpha: 0.65) : AppColors.line,
        ),
        showCheckmark: false,
      ),
    );
  }
}

class _DetectorFilters extends StatelessWidget {
  const _DetectorFilters({required this.selected, required this.onSelected});

  final String? selected;
  final ValueChanged<String?> onSelected;

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      scrollDirection: Axis.horizontal,
      child: Row(
        children: [
          _chip('ALL', null),
          for (final entry in detectorLabels.entries)
            _chip(entry.value, entry.key),
        ],
      ),
    );
  }

  Widget _chip(String label, String? value) {
    final active = selected == value;
    return Padding(
      padding: const EdgeInsets.only(right: 8),
      child: ChoiceChip(
        label: Text(
          label,
          style: TextStyle(
            color: active ? AppColors.cyan : AppColors.muted,
            fontSize: 9.5,
            fontWeight: FontWeight.w700,
            letterSpacing: 0.6,
          ),
        ),
        selected: active,
        onSelected: (_) => onSelected(value),
        selectedColor: AppColors.cyan.withValues(alpha: 0.12),
        side: BorderSide(
          color: active
              ? AppColors.cyan.withValues(alpha: 0.6)
              : AppColors.line,
        ),
        showCheckmark: false,
      ),
    );
  }
}

class _AlertCard extends StatelessWidget {
  const _AlertCard({required this.alert, required this.onTap});

  final AlertItem alert;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final color = AppColors.forSeverity(alert.severity);
    return Material(
      color: Colors.transparent,
      child: InkWell(
        borderRadius: BorderRadius.circular(14),
        onTap: onTap,
        child: Container(
          decoration: BoxDecoration(
            color: AppColors.panel,
            borderRadius: BorderRadius.circular(14),
            border: Border.all(color: color.withValues(alpha: 0.26)),
          ),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Container(
                width: 4,
                decoration: BoxDecoration(
                  color: color,
                  borderRadius: const BorderRadius.horizontal(
                    left: Radius.circular(14),
                  ),
                ),
              ),
              Expanded(
                child: Padding(
                  padding: const EdgeInsets.fromLTRB(12, 12, 12, 12),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          _SeverityBadge(
                            severity: alert.severity,
                            color: color,
                          ),
                          const SizedBox(width: 8),
                          Expanded(
                            child: Text(
                              (detectorLabels[alert.detector] ?? alert.detector)
                                  .toUpperCase(),
                              overflow: TextOverflow.ellipsis,
                              style: const TextStyle(
                                color: AppColors.muted,
                                fontSize: 9,
                                letterSpacing: 1.2,
                                fontWeight: FontWeight.w700,
                              ),
                            ),
                          ),
                          Text(
                            relativeTime(alert.lastSeen),
                            style: const TextStyle(
                              color: AppColors.muted,
                              fontSize: 9.5,
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 8),
                      Text(
                        alert.title,
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(
                          color: AppColors.text,
                          fontSize: 13,
                          fontWeight: FontWeight.w700,
                          height: 1.35,
                        ),
                      ),
                      const SizedBox(height: 5),
                      Text(
                        alert.description,
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(
                          color: AppColors.muted,
                          fontSize: 10.5,
                          height: 1.45,
                        ),
                      ),
                      const SizedBox(height: 9),
                      Row(
                        children: [
                          const Icon(
                            Icons.hub_outlined,
                            color: AppColors.muted,
                            size: 12,
                          ),
                          const SizedBox(width: 4),
                          Expanded(
                            child: Text(
                              alert.entity,
                              overflow: TextOverflow.ellipsis,
                              style: const TextStyle(
                                color: AppColors.cyan,
                                fontSize: 10,
                              ),
                            ),
                          ),
                          const SizedBox(width: 8),
                          Text(
                            '${alert.eventCount} '
                            '${alert.eventCount == 1 ? 'EVENT' : 'EVENTS'}',
                            style: const TextStyle(
                              color: AppColors.muted,
                              fontSize: 9,
                              letterSpacing: 0.8,
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _SeverityBadge extends StatelessWidget {
  const _SeverityBadge({required this.severity, required this.color});

  final String severity;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2.5),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: color.withValues(alpha: 0.55)),
      ),
      child: Text(
        severity.toUpperCase(),
        style: TextStyle(
          color: color,
          fontSize: 8,
          fontWeight: FontWeight.w800,
          letterSpacing: 0.9,
        ),
      ),
    );
  }
}

class _EmptyState extends StatelessWidget {
  const _EmptyState();

  @override
  Widget build(BuildContext context) {
    return GlassPanel(
      padding: const EdgeInsets.symmetric(vertical: 34, horizontal: 20),
      child: Column(
        children: const [
          Icon(Icons.shield_outlined, color: AppColors.muted, size: 34),
          SizedBox(height: 12),
          Text(
            'NO ALERTS MATCH',
            style: TextStyle(
              color: AppColors.text,
              fontSize: 12,
              fontWeight: FontWeight.w700,
              letterSpacing: 1.4,
            ),
          ),
          SizedBox(height: 6),
          Text(
            'Adjust the filters or run a detection scan on the server.',
            textAlign: TextAlign.center,
            style: TextStyle(color: AppColors.muted, fontSize: 10.5),
          ),
        ],
      ),
    );
  }
}

/// Shown when the first API call fails. It explains that the client is only a
/// viewer, shows the exact command that starts the server, and offers a way to
/// switch to another address without wiping and retyping everything.
class ConnectionLostView extends StatefulWidget {
  const ConnectionLostView({
    super.key,
    required this.message,
    required this.serverUrl,
    required this.onRetry,
    required this.onChangeServer,
  });

  final String message;
  final String serverUrl;
  final Future<void> Function({bool silent}) onRetry;
  final Future<void> Function() onChangeServer;

  @override
  State<ConnectionLostView> createState() => _ConnectionLostViewState();
}

class _ConnectionLostViewState extends State<ConnectionLostView> {
  int _attempt = 0;

  bool get _isPhone =>
      !kIsWeb && defaultTargetPlatform == TargetPlatform.android;

  String get _command => serveCommandFor(widget.serverUrl, lan: _isPhone);

  Future<void> _copyCommand() async {
    await Clipboard.setData(ClipboardData(text: _command));
    if (!mounted) return;
    ScaffoldMessenger.of(context)
        .showSnackBar(const SnackBar(content: Text('Start command copied')));
  }

  Future<void> _retry() async {
    // Replay the swing so the attempt is visible, then ask the API again.
    setState(() => _attempt++);
    await widget.onRetry();
  }

  @override
  Widget build(BuildContext context) {
    return Center(
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 520),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              GolfAttempt(attempt: _attempt),
              const SizedBox(height: 4),
              const Text(
                'CONNECTION LOST',
                style: TextStyle(
                  color: AppColors.text,
                  fontSize: 14,
                  fontWeight: FontWeight.w800,
                  letterSpacing: 2,
                ),
              ),
              const SizedBox(height: 8),
              Text(
                widget.message,
                textAlign: TextAlign.center,
                style: const TextStyle(
                  color: AppColors.muted,
                  fontSize: 11.5,
                  height: 1.5,
                ),
              ),
              const SizedBox(height: 16),
              _AddressPill(url: widget.serverUrl),
              const SizedBox(height: 18),
              _StartServerHint(command: _command, onCopy: _copyCommand),
              const SizedBox(height: 22),
              Wrap(
                alignment: WrapAlignment.center,
                spacing: 10,
                runSpacing: 10,
                children: [
                  FilledButton.icon(
                    style: FilledButton.styleFrom(
                      minimumSize: const Size(0, 50),
                      padding: const EdgeInsets.symmetric(horizontal: 22),
                    ),
                    onPressed: _retry,
                    icon: const Icon(Icons.refresh, size: 18),
                    label: const Text('RETRY'),
                  ),
                  OutlinedButton.icon(
                    style: OutlinedButton.styleFrom(
                      foregroundColor: AppColors.cyan,
                      side: const BorderSide(color: AppColors.line),
                      minimumSize: const Size(0, 50),
                      padding: const EdgeInsets.symmetric(horizontal: 18),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(12),
                      ),
                      textStyle: const TextStyle(
                        fontSize: 13,
                        fontWeight: FontWeight.w700,
                        letterSpacing: 1.2,
                      ),
                    ),
                    onPressed: widget.onChangeServer,
                    icon: const Icon(Icons.dns_outlined, size: 18),
                    label: const Text('CHANGE SERVER'),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _AddressPill extends StatelessWidget {
  const _AddressPill({required this.url});

  final String url;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 9),
      decoration: BoxDecoration(
        color: AppColors.panel,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: AppColors.line),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Icon(Icons.dns_outlined, size: 14, color: AppColors.muted),
          const SizedBox(width: 8),
          Flexible(
            child: Text(
              url,
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(color: AppColors.text, fontSize: 11.5),
            ),
          ),
        ],
      ),
    );
  }
}

class _StartServerHint extends StatelessWidget {
  const _StartServerHint({required this.command, required this.onCopy});

  final String command;
  final VoidCallback onCopy;

  @override
  Widget build(BuildContext context) {
    return GlassPanel(
      padding: const EdgeInsets.all(14),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Row(
            children: [
              Icon(Icons.terminal, color: AppColors.violet, size: 16),
              SizedBox(width: 8),
              Text(
                'START THE API',
                style: TextStyle(
                  color: AppColors.violet,
                  fontSize: 10.5,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 1.8,
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          const Text(
            'This app only displays alerts; it has no data of its own. Start '
            'the server on your computer, keep that window open, then retry.',
            style: TextStyle(
              color: AppColors.muted,
              fontSize: 11.5,
              height: 1.5,
            ),
          ),
          const SizedBox(height: 12),
          Container(
            padding: const EdgeInsets.fromLTRB(12, 6, 4, 6),
            decoration: BoxDecoration(
              color: AppColors.background,
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: AppColors.line),
            ),
            child: Row(
              children: [
                Expanded(
                  child: SelectableText(
                    command,
                    style: const TextStyle(
                      color: AppColors.text,
                      fontSize: 10.5,
                      height: 1.6,
                    ),
                  ),
                ),
                IconButton(
                  onPressed: onCopy,
                  tooltip: 'Copy command',
                  icon: const Icon(
                    Icons.copy_all_outlined,
                    size: 18,
                    color: AppColors.cyan,
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 8),
          const Text(
            'Use the same token that is saved in Settings.',
            style: TextStyle(color: AppColors.muted, fontSize: 10.5),
          ),
        ],
      ),
    );
  }
}
