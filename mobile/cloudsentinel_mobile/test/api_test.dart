import 'dart:async';

import 'package:cloudsentinel_mobile/api.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

void main() {
  group('normalizeBaseUrl', () {
    test('adds http and trims trailing slashes', () {
      expect(
        ApiClient.normalizeBaseUrl(' 192.168.1.10:8080// '),
        'http://192.168.1.10:8080',
      );
      expect(
        ApiClient.normalizeBaseUrl('https://sentinel.example.com/'),
        'https://sentinel.example.com',
      );
      expect(ApiClient.normalizeBaseUrl(''), '');
    });
  });

  group('models', () {
    test('summary parses counts and tolerates missing fields', () {
      final summary = SummaryData.fromJson(const {
        'total_alerts': 10,
        'by_severity': {'critical': 5, 'high': '5'},
        'by_detector': {'brute_force': 6},
        'affected_entities': 4,
        'generated_at': '2026-10-28T18:00:00+00:00',
        'scan_enabled': true,
      });

      expect(summary.totalAlerts, 10);
      expect(summary.count('critical'), 5);
      // Non-numeric values fall back to zero rather than crashing.
      expect(summary.count('high'), 5);
      expect(summary.affectedEntities, 4);
      expect(summary.scanEnabled, isTrue);

      final empty = SummaryData.fromJson(const {});
      expect(empty.totalAlerts, 0);
      expect(empty.scanEnabled, isFalse);
      expect(empty.count('critical'), 0);
    });

    test('alert parses timestamps, evidence and defaults', () {
      final alert = AlertItem.fromJson(const {
        'id': 7,
        'fingerprint': 'abc123',
        'detector': 'brute_force',
        'severity': 'critical',
        'title': 'Repeated failed logins',
        'description': 'Six failures from one IP',
        'entity': 'carol',
        'entity_type': 'user',
        'event_count': 6,
        'first_seen': '2026-04-01T10:00:00Z',
        'last_seen': '2026-04-01T10:05:00Z',
        'evidence': {
          'source_ips': ['203.0.113.99'],
          'failures': 6,
        },
      });

      expect(alert.id, 7);
      expect(alert.firstSeen, isNotNull);
      expect(alert.lastSeen!.isAfter(alert.firstSeen!), isTrue);
      expect(alert.evidence['failures'], 6);

      final sparse = AlertItem.fromJson(const {'id': 1});
      expect(sparse.title, 'Untitled finding');
      expect(sparse.severity, 'info');
      expect(sparse.evidence, isEmpty);
      expect(sparse.firstSeen, isNull);
    });

    test('alerts page ignores malformed entries', () {
      final page = AlertsPage.fromJson(const {
        'total': 2,
        'alerts': [
          {'id': 1, 'title': 'A'},
          'not-an-object',
          {'id': 2, 'title': 'B'},
        ],
      });

      expect(page.total, 2);
      expect(page.alerts.length, 2);
      expect(page.alerts.last.id, 2);

      expect(AlertsPage.fromJson(const {}).alerts, isEmpty);
    });
  });

  group('ApiClient', () {
    test('fetchSummary sends the token and parses the payload', () async {
      final client = ApiClient(
        baseUrl: 'http://example.test:8080/',
        token: ' secret ',
        httpClient: MockClient((request) async {
          expect(request.method, 'GET');
          expect(request.url.toString(), 'http://example.test:8080/api/summary');
          expect(request.headers['X-API-Token'], 'secret');
          return http.Response(
            '{"total_alerts":3,"by_severity":{"critical":1},'
            '"by_detector":{"brute_force":1},"affected_entities":2,'
            '"scan_enabled":false}',
            200,
            headers: {'content-type': 'application/json'},
          );
        }),
      );

      final summary = await client.fetchSummary();
      expect(summary.totalAlerts, 3);
      expect(summary.count('critical'), 1);
    });

    test('401 raises a typed ApiException', () async {
      final client = ApiClient(
        baseUrl: 'http://example.test',
        token: 'bad',
        httpClient: MockClient(
          (_) async => http.Response('{"detail":"nope"}', 401),
        ),
      );

      await expectLater(
        client.fetchSummary(),
        throwsA(
          isA<ApiException>()
              .having((error) => error.statusCode, 'statusCode', 401)
              .having((error) => error.message, 'message', contains('token')),
        ),
      );
    });

    test('fetchAlerts encodes filters and parses results', () async {
      late Uri seen;
      final client = ApiClient(
        baseUrl: 'http://example.test',
        httpClient: MockClient((request) async {
          seen = request.url;
          return http.Response(
            '{"total":1,"count":1,"limit":50,"offset":0,"alerts":['
            '{"id":9,"severity":"high","title":"Public bucket",'
            '"entity":"bucket-a","event_count":2}]}',
            200,
          );
        }),
      );

      final page = await client.fetchAlerts(
        severity: 'high',
        detector: 'public_storage',
        search: ' bucket ',
        limit: 50,
      );

      expect(seen.queryParameters['severity'], 'high');
      expect(seen.queryParameters['detector'], 'public_storage');
      expect(seen.queryParameters['search'], 'bucket');
      expect(seen.queryParameters['limit'], '50');
      expect(page.total, 1);
      expect(page.alerts.single.entity, 'bucket-a');
    });

    test('scan surfaces disabled and success responses', () async {
      var allowed = false;
      final client = ApiClient(
        baseUrl: 'http://example.test',
        httpClient: MockClient((request) async {
          if (!allowed) return http.Response('{"detail":"disabled"}', 403);
          return http.Response(
            '{"status":"ok","events_scanned":12,"alerts":2}',
            200,
          );
        }),
      );

      await expectLater(
        client.scan(),
        throwsA(
          isA<ApiException>().having(
            (error) => error.message,
            'message',
            contains('disabled'),
          ),
        ),
      );

      allowed = true;
      final result = await client.scan(reset: true);
      expect(result['events_scanned'], 12);
    });

    test('connection failures are reported as ApiException', () async {
      final client = ApiClient(
        baseUrl: 'http://example.test',
        httpClient: MockClient(
          (_) async => throw http.ClientException('connection refused'),
        ),
      );

      await expectLater(
        client.health(),
        throwsA(
          isA<ApiException>().having(
            (error) => error.message,
            'message',
            contains('Cannot reach'),
          ),
        ),
      );
    });
  });

  group('formatting', () {
    test('relativeTime bucketed labels', () {
      final now = DateTime.now();
      expect(relativeTime(null), '—');
      expect(relativeTime(now), 'just now');
      expect(relativeTime(now.subtract(const Duration(minutes: 5))), '5m ago');
      expect(relativeTime(now.subtract(const Duration(hours: 3))), '3h ago');
      expect(relativeTime(now.subtract(const Duration(days: 2))), '2d ago');
      expect(
        relativeTime(now.subtract(const Duration(days: 40))),
        matches(RegExp(r'^\d{4}-\d{2}-\d{2}$')),
      );
    });

    test('absoluteTime includes an offset', () {
      expect(absoluteTime(null), '—');
      final formatted = absoluteTime(DateTime.utc(2026, 4, 1, 10, 5));
      expect(formatted, contains('2026-04-01'));
      expect(formatted, contains('UTC'));
    });

    test('describeError prefers friendly messages', () {
      expect(describeError(ApiException('boom', 500)), 'boom');
      expect(describeError(TimeoutException('slow')), 'Connection timed out');
      expect(
        describeError(const FormatException('bad')),
        contains('FormatException'),
      );
    });
  });
}
