import 'package:cloudsentinel_mobile/main.dart';
import 'package:cloudsentinel_mobile/screens/connect_screen.dart';
import 'package:cloudsentinel_mobile/screens/dashboard_screen.dart';
import 'package:cloudsentinel_mobile/serve_command.dart';
import 'package:cloudsentinel_mobile/theme.dart';
import 'package:cloudsentinel_mobile/widgets/golf_attempt.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

Widget _wrap(Widget child) => MaterialApp(
  theme: buildTheme(),
  home: Scaffold(body: child),
);

void main() {
  group('serveCommandFor', () {
    test('uses the port from the client URL', () {
      expect(
        serveCommandFor('http://127.0.0.1:8091'),
        'python -m cloudsentinel serve --port 8091 --token YOUR_TOKEN',
      );
    });

    test('binds all interfaces when the client is a phone', () {
      expect(
        serveCommandFor('http://192.168.1.42:8080', lan: true),
        'python -m cloudsentinel serve --host 0.0.0.0 --port 8080 '
        '--token YOUR_TOKEN',
      );
    });

    test('omits the port when the URL has none', () {
      expect(
        serveCommandFor('http://example.test'),
        'python -m cloudsentinel serve --token YOUR_TOKEN',
      );
    });

    test('tolerates empty and malformed input', () {
      expect(
        serveCommandFor(''),
        'python -m cloudsentinel serve --token YOUR_TOKEN',
      );
      expect(
        serveCommandFor('not a url'),
        'python -m cloudsentinel serve --token YOUR_TOKEN',
      );
    });
  });

  testWidgets('connection lost view explains the server requirement', (
    tester,
  ) async {
    var retries = 0;
    var changes = 0;

    await tester.pumpWidget(
      _wrap(
        ConnectionLostView(
          message: 'Cannot reach http://127.0.0.1:8091',
          serverUrl: 'http://127.0.0.1:8091',
          onRetry: ({bool silent = false}) async {
            retries++;
          },
          onChangeServer: () async {
            changes++;
          },
        ),
      ),
    );

    expect(find.text('CONNECTION LOST'), findsOneWidget);
    expect(find.text('START THE API'), findsOneWidget);
    expect(find.text('CHANGE SERVER'), findsOneWidget);
    expect(find.textContaining('http://127.0.0.1:8091'), findsWidgets);

    final command = tester.widget<SelectableText>(find.byType(SelectableText));
    expect(command.data, contains('--port 8091'));

    await tester.tap(find.text('CHANGE SERVER'));
    await tester.pump();
    expect(changes, 1);
    expect(retries, 0);

    await tester.tap(find.text('RETRY'));
    await tester.pump();
    expect(retries, 1);
    expect(tester.binding.hasScheduledFrame, isTrue);
    await tester.pumpAndSettle();
  });

  testWidgets('golf animation plays once, then replays on demand', (
    tester,
  ) async {
    final semantics = tester.ensureSemantics();

    await tester.pumpWidget(_wrap(const GolfAttempt()));
    expect(
      find.bySemanticsLabel(
        'A golf ball rolls to a stop just short of the hole',
      ),
      findsOneWidget,
    );

    await tester.pump(const Duration(milliseconds: 600));
    expect(tester.binding.hasScheduledFrame, isTrue);

    await tester.pumpAndSettle();
    expect(tester.binding.hasScheduledFrame, isFalse);

    await tester.pumpWidget(_wrap(const GolfAttempt(attempt: 1)));
    await tester.pump(const Duration(milliseconds: 120));
    expect(tester.binding.hasScheduledFrame, isTrue);
    await tester.pumpAndSettle();

    semantics.dispose();
  });

  testWidgets('golf animation honours reduced motion', (tester) async {
    await tester.pumpWidget(
      _wrap(
        MediaQuery(
          data: const MediaQueryData(disableAnimations: true),
          child: const GolfAttempt(),
        ),
      ),
    );

    await tester.pump(const Duration(milliseconds: 50));
    expect(tester.binding.hasScheduledFrame, isFalse);
  });

  testWidgets('copy button puts the start command on the clipboard', (
    tester,
  ) async {
    final calls = <MethodCall>[];
    tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
      SystemChannels.platform,
      (call) async {
        if (call.method == 'Clipboard.setData') calls.add(call);
        return null;
      },
    );
    addTearDown(
      () => tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
        SystemChannels.platform,
        null,
      ),
    );

    await tester.pumpWidget(
      _wrap(
        ConnectionLostView(
          message: 'Cannot reach http://127.0.0.1:8091',
          serverUrl: 'http://127.0.0.1:8091',
          onRetry: ({bool silent = false}) async {},
          onChangeServer: () async {},
        ),
      ),
    );

    await tester.tap(find.byTooltip('Copy command'));
    await tester.pump();

    expect(calls, hasLength(1));
    final arguments = calls.single.arguments as Map<Object?, Object?>;
    expect(arguments['text'], contains('python -m cloudsentinel serve'));
    expect(arguments['text'], contains('--port 8091'));
    expect(find.text('Start command copied'), findsOneWidget);
  });

  testWidgets('connect screen pre-fills the failed connection', (tester) async {
    await tester.pumpWidget(
      MaterialApp(
        theme: buildTheme(),
        home: ConnectScreen(
          onConnected: (_) async {},
          initialUrl: 'http://127.0.0.1:8091',
          initialToken: 'testtoken',
        ),
      ),
    );

    final fields = tester
        .widgetList<TextField>(find.byType(TextField))
        .toList();
    expect(fields[0].controller!.text, 'http://127.0.0.1:8091');
    expect(fields[1].controller!.text, 'testtoken');
  });

  testWidgets('change server clears the saved connection and pre-fills it', (
    tester,
  ) async {
    SharedPreferences.setMockInitialValues({
      'server_url': 'http://127.0.0.1:8091',
      'api_token': 'testtoken',
    });

    await tester.pumpWidget(const CloudSentinelApp());
    await tester.pumpAndSettle();

    expect(find.text('CHANGE SERVER'), findsOneWidget);

    await tester.tap(find.text('CHANGE SERVER'));
    await tester.pumpAndSettle();

    expect(find.byType(ConnectScreen), findsOneWidget);
    final fields = tester
        .widgetList<TextField>(find.byType(TextField))
        .toList();
    expect(fields[0].controller!.text, 'http://127.0.0.1:8091');
    expect(fields[1].controller!.text, 'testtoken');

    final prefs = await SharedPreferences.getInstance();
    expect(prefs.getString('server_url'), isNull);
    expect(prefs.getString('api_token'), isNull);
  });
}
