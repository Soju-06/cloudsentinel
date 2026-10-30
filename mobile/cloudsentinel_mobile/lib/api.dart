import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;

const detectorLabels = <String, String>{
  'brute_force': 'BRUTE FORCE',
  'impossible_travel': 'IMPOSSIBLE TRAVEL',
  'public_storage': 'PUBLIC STORAGE',
  'iam_permissions': 'IAM PERMISSIONS',
  'mfa_changes': 'MFA CHANGES',
  'root_usage': 'ROOT USAGE',
  'access_key_creation': 'ACCESS KEYS',
  'security_group_open': 'OPEN SECURITY GROUP',
  'cloudtrail_tampering': 'CLOUDTRAIL TAMPERING',
};

class ApiException implements Exception {
  ApiException(this.message, [this.statusCode]);

  final String message;
  final int? statusCode;

  @override
  String toString() => message;
}

class SummaryData {
  const SummaryData({
    required this.totalAlerts,
    required this.bySeverity,
    required this.byDetector,
    required this.affectedEntities,
    required this.generatedAt,
    required this.scanEnabled,
  });

  final int totalAlerts;
  final Map<String, int> bySeverity;
  final Map<String, int> byDetector;
  final int affectedEntities;
  final String? generatedAt;
  final bool scanEnabled;

  factory SummaryData.fromJson(Map<String, dynamic> json) {
    return SummaryData(
      totalAlerts: (json['total_alerts'] as num?)?.toInt() ?? 0,
      bySeverity: _intMap(json['by_severity']),
      byDetector: _intMap(json['by_detector']),
      affectedEntities: (json['affected_entities'] as num?)?.toInt() ?? 0,
      generatedAt: json['generated_at'] as String?,
      scanEnabled: json['scan_enabled'] == true,
    );
  }

  int count(String severity) => bySeverity[severity] ?? 0;
}

class AlertItem {
  const AlertItem({
    required this.id,
    required this.fingerprint,
    required this.detector,
    required this.severity,
    required this.title,
    required this.description,
    required this.entity,
    required this.entityType,
    required this.eventCount,
    required this.firstSeen,
    required this.lastSeen,
    required this.evidence,
    this.status = 'open',
    this.assignee,
    this.triagedAt,
  });

  final int id;
  final String fingerprint;
  final String detector;
  final String severity;
  final String title;
  final String description;
  final String entity;
  final String entityType;
  final int eventCount;
  final DateTime? firstSeen;
  final DateTime? lastSeen;
  final Map<String, dynamic> evidence;
  final String status;
  final String? assignee;
  final DateTime? triagedAt;

  factory AlertItem.fromJson(Map<String, dynamic> json) {
    return AlertItem(
      id: (json['id'] as num?)?.toInt() ?? 0,
      fingerprint: json['fingerprint'] as String? ?? '',
      detector: json['detector'] as String? ?? 'unknown',
      severity: json['severity'] as String? ?? 'info',
      title: json['title'] as String? ?? 'Untitled finding',
      description: json['description'] as String? ?? '',
      entity: json['entity'] as String? ?? 'unknown',
      entityType: json['entity_type'] as String? ?? '',
      eventCount: (json['event_count'] as num?)?.toInt() ?? 0,
      firstSeen: _date(json['first_seen']),
      lastSeen: _date(json['last_seen']),
      evidence: (json['evidence'] is Map)
          ? Map<String, dynamic>.from(json['evidence'] as Map)
          : const {},
      status: json['status'] as String? ?? 'open',
      assignee: json['assignee'] as String?,
      triagedAt: _date(json['triaged_at']),
    );
  }
}

class AlertsPage {
  const AlertsPage({required this.total, required this.alerts});

  final int total;
  final List<AlertItem> alerts;

  factory AlertsPage.fromJson(Map<String, dynamic> json) {
    final raw = json['alerts'];
    return AlertsPage(
      total: (json['total'] as num?)?.toInt() ?? 0,
      alerts: raw is List
          ? raw
                .whereType<Map>()
                .map(
                  (item) => AlertItem.fromJson(Map<String, dynamic>.from(item)),
                )
                .toList(growable: false)
          : const [],
    );
  }
}

class ApiClient {
  ApiClient({
    required String baseUrl,
    String token = '',
    http.Client? httpClient,
  }) : baseUrl = normalizeBaseUrl(baseUrl),
       token = token.trim(),
       _client = httpClient ?? http.Client();

  final String baseUrl;
  final String token;
  final http.Client _client;

  static String normalizeBaseUrl(String input) {
    var value = input.trim();
    if (value.isEmpty) return value;
    if (!value.startsWith('http://') && !value.startsWith('https://')) {
      value = 'http://$value';
    }
    while (value.endsWith('/')) {
      value = value.substring(0, value.length - 1);
    }
    return value;
  }

  Map<String, String> get _headers => {
    'Accept': 'application/json',
    if (token.isNotEmpty) 'X-API-Token': token,
  };

  Uri _uri(String path, [Map<String, String>? query]) {
    final uri = Uri.parse('$baseUrl$path');
    return query == null || query.isEmpty
        ? uri
        : uri.replace(queryParameters: query);
  }

  Future<Map<String, dynamic>> _get(
    String path, [
    Map<String, String>? query,
  ]) async {
    http.Response response;
    try {
      response = await _client
          .get(_uri(path, query), headers: _headers)
          .timeout(const Duration(seconds: 10));
    } on TimeoutException {
      throw ApiException('Connection timed out. Is the server running?');
    } on http.ClientException {
      throw ApiException('Cannot reach $baseUrl');
    }

    if (response.statusCode == 401) {
      throw ApiException('Invalid or missing API token', 401);
    }
    if (response.statusCode != 200) {
      throw ApiException(
        'Server returned HTTP ${response.statusCode}',
        response.statusCode,
      );
    }

    final decoded = jsonDecode(response.body);
    if (decoded is! Map<String, dynamic>) {
      throw ApiException('Unexpected response from server');
    }
    return decoded;
  }

  Future<Map<String, dynamic>> health() => _get('/health');

  Future<SummaryData> fetchSummary() async {
    return SummaryData.fromJson(await _get('/api/summary'));
  }

  Future<AlertsPage> fetchAlerts({
    String? severity,
    String? detector,
    String? status,
    String? search,
    int limit = 200,
  }) async {
    final query = <String, String>{'limit': '$limit'};
    if (severity != null && severity.isNotEmpty) query['severity'] = severity;
    if (detector != null && detector.isNotEmpty) query['detector'] = detector;
    if (status != null && status.isNotEmpty) query['status'] = status;
    if (search != null && search.trim().isNotEmpty) {
      query['search'] = search.trim();
    }
    return AlertsPage.fromJson(await _get('/api/alerts', query));
  }

  /// Acknowledge, assign, close or reopen one alert.
  ///
  /// Pass [updateAssignee] with [assignee] set to a name, or `null` to clear
  /// it. Omitted parameters are left untouched by the server.
  Future<AlertItem> updateTriage(
    int alertId, {
    String? status,
    String? assignee,
    bool updateAssignee = false,
  }) async {
    if (status == null && !updateAssignee) {
      throw ApiException('Nothing to update', 400);
    }

    final body = <String, dynamic>{
      'status': ?status,
      if (updateAssignee) 'assignee': assignee,
    };

    http.Response response;
    try {
      response = await _client
          .patch(
            _uri('/api/alerts/$alertId'),
            headers: {..._headers, 'Content-Type': 'application/json'},
            body: jsonEncode(body),
          )
          .timeout(const Duration(seconds: 10));
    } on TimeoutException {
      throw ApiException('Connection timed out. Is the server running?');
    } on http.ClientException {
      throw ApiException('Cannot reach $baseUrl');
    }

    if (response.statusCode == 401) {
      throw ApiException('Invalid or missing API token', 401);
    }
    if (response.statusCode == 200) {
      final decoded = jsonDecode(response.body);
      if (decoded is! Map<String, dynamic>) {
        throw ApiException('Unexpected response from server');
      }
      return AlertItem.fromJson(decoded);
    }

    final detail = _detail(response.body);
    if (response.statusCode == 404) {
      throw ApiException(detail ?? 'Alert not found', 404);
    }
    if (response.statusCode == 409) {
      throw ApiException(detail ?? 'That status change is not allowed', 409);
    }
    throw ApiException(
      detail ?? 'Server returned HTTP ${response.statusCode}',
      response.statusCode,
    );
  }

  Future<Map<String, dynamic>> scan({bool reset = false}) async {
    final uri = _uri('/api/scan', {'reset': '$reset'});
    final response = await _client
        .post(uri, headers: _headers)
        .timeout(const Duration(seconds: 120));
    if (response.statusCode == 401) {
      throw ApiException('Invalid or missing API token', 401);
    }
    if (response.statusCode == 403) {
      throw ApiException('Scanning is disabled on the server');
    }
    if (response.statusCode != 200) {
      throw ApiException('Scan failed (HTTP ${response.statusCode})');
    }
    return jsonDecode(response.body) as Map<String, dynamic>;
  }
}

Map<String, int> _intMap(Object? value) {
  if (value is! Map) return const {};
  return {
    for (final entry in value.entries) '${entry.key}': _asInt(entry.value),
  };
}

int _asInt(Object? value) {
  if (value is num) return value.toInt();
  if (value is String) return int.tryParse(value) ?? 0;
  return 0;
}

DateTime? _date(Object? value) {
  if (value is! String || value.isEmpty) return null;
  return DateTime.tryParse(value);
}

String? _detail(String body) {
  try {
    final decoded = jsonDecode(body);
    if (decoded is Map && decoded['detail'] is String) {
      return decoded['detail'] as String;
    }
  } catch (_) {
    // Not JSON: fall back to a generic message.
  }
  return null;
}

String describeError(Object error) {
  if (error is ApiException) return error.message;
  if (error is TimeoutException) return 'Connection timed out';
  return error.toString();
}

String relativeTime(DateTime? moment) {
  if (moment == null) return '—';
  final delta = DateTime.now().difference(moment.toLocal());
  if (delta.isNegative) return 'just now';
  if (delta.inMinutes < 1) return 'just now';
  if (delta.inMinutes < 60) return '${delta.inMinutes}m ago';
  if (delta.inHours < 24) return '${delta.inHours}h ago';
  if (delta.inDays < 30) return '${delta.inDays}d ago';
  final local = moment.toLocal();
  return '${local.year}-${_two(local.month)}-${_two(local.day)}';
}

String absoluteTime(DateTime? moment) {
  if (moment == null) return '—';
  final local = moment.toLocal();
  return '${local.year}-${_two(local.month)}-${_two(local.day)} '
      '${_two(local.hour)}:${_two(local.minute)} UTC${_offset(local)}';
}

String _two(int value) => value.toString().padLeft(2, '0');

String _offset(DateTime local) {
  final offset = local.timeZoneOffset;
  final sign = offset.isNegative ? '-' : '+';
  final hours = _two(offset.inHours.abs());
  final minutes = _two(offset.inMinutes.abs() % 60);
  return '$sign$hours:$minutes';
}
