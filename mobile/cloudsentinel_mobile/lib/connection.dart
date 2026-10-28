import 'api.dart';

class Connection {
  const Connection({required this.baseUrl, required this.token});

  final String baseUrl;
  final String token;

  ApiClient get client => ApiClient(baseUrl: baseUrl, token: token);

  String get host {
    final uri = Uri.tryParse(baseUrl);
    if (uri == null || uri.host.isEmpty) return baseUrl;
    return uri.hasPort ? '${uri.host}:${uri.port}' : uri.host;
  }
}
