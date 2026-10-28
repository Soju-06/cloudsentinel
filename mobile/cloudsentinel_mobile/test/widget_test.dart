import 'package:cloudsentinel_mobile/main.dart';
import 'package:cloudsentinel_mobile/screens/connect_screen.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues({});
  });

  testWidgets('boots into the connect screen when no server is saved', (
    tester,
  ) async {
    await tester.pumpWidget(const CloudSentinelApp());
    await tester.pumpAndSettle();

    expect(find.byType(ConnectScreen), findsOneWidget);
    expect(find.text('CLOUDSENTINEL'), findsOneWidget);
    expect(find.text('CONNECT TO YOUR SERVER'), findsOneWidget);
    expect(find.text('CONNECT'), findsOneWidget);
    expect(find.text('START THE API'), findsOneWidget);
  });

  testWidgets('rejects an empty server URL without contacting the network', (
    tester,
  ) async {
    await tester.pumpWidget(const CloudSentinelApp());
    await tester.pumpAndSettle();

    await tester.enterText(find.byType(TextField).first, '   ');
    await tester.tap(find.text('CONNECT'));
    await tester.pump();

    expect(find.text('Enter the CloudSentinel server URL.'), findsOneWidget);
    expect(find.byType(ConnectScreen), findsOneWidget);
  });

  testWidgets('connect screen shows the token field as masked', (
    tester,
  ) async {
    await tester.pumpWidget(const CloudSentinelApp());
    await tester.pumpAndSettle();

    final fields = tester.widgetList<TextField>(find.byType(TextField)).toList();
    expect(fields.length, 2);
    expect(fields[1].obscureText, isTrue);
    expect(find.byIcon(Icons.visibility_outlined), findsOneWidget);

    await tester.tap(find.byIcon(Icons.visibility_outlined));
    await tester.pump();

    final updated = tester
        .widgetList<TextField>(find.byType(TextField))
        .toList();
    expect(updated[1].obscureText, isFalse);
    expect(find.byIcon(Icons.visibility_off_outlined), findsOneWidget);
  });
}
