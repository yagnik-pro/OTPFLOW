import 'dart:convert';
import 'dart:io';
import 'package:dio/dio.dart';
import 'package:dio_cookie_manager/dio_cookie_manager.dart';
import 'package:cookie_jar/cookie_jar.dart';
import 'package:path_provider/path_provider.dart';

import '../models/account.dart';
import '../models/otp_entry.dart';

/// Thrown when the saved session is no longer valid and a re-login is needed.
class SessionExpired implements Exception {
  final String message;
  SessionExpired([this.message = 'Session expired']);
  @override
  String toString() => message;
}

/// Thrown for anything the user should read (wrong password, captcha, etc.)
class MeeshoError implements Exception {
  final String message;
  MeeshoError(this.message);
  @override
  String toString() => message;
}

/// Talks to the Meesho supplier panel's own API.
///
/// Endpoints used (same ones the web panel calls):
///   POST /api/container/user/v2-login             → login, returns token + sets cookies
///   GET  /api/container/supplier/getSupplierDetails → store name, supplier id
///   POST /api/fulfillment/returnRto/fetchDeliveryOTPs → the return OTPs
///   POST /api/payouts/payments/all-ui-data2       → payments summary
class MeeshoApi {
  static const base = 'https://supplier.meesho.com';
  static const _ua =
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';

  final String accountId;
  late final Dio _dio;
  late final PersistCookieJar _jar;
  bool _ready = false;

  MeeshoApi(this.accountId);

  Future<void> _init() async {
    if (_ready) return;
    final dir = await getApplicationDocumentsDirectory();
    _jar = PersistCookieJar(
      ignoreExpires: true,
      storage: FileStorage('${dir.path}/cookies/$accountId/'),
    );
    _dio = Dio(BaseOptions(
      baseUrl: base,
      connectTimeout: const Duration(seconds: 20),
      receiveTimeout: const Duration(seconds: 25),
      headers: {
        'User-Agent': _ua,
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json',
        'Origin': base,
        'Referer': '$base/panel/v3/new/root/login',
      },
      // we check status ourselves
      validateStatus: (s) => s != null && s < 500,
    ));
    _dio.interceptors.add(CookieManager(_jar));
    _ready = true;
  }

  Future<void> clearSession() async {
    await _init();
    await _jar.deleteAll();
  }

  Future<bool> hasSession() async {
    await _init();
    final cookies = await _jar.loadForRequest(Uri.parse(base));
    return cookies.isNotEmpty;
  }

  void _applyToken(String? token) {
    if (token == null || token.isEmpty) return;
    _dio.options.headers['Authorization'] = 'Bearer $token';
    _dio.options.headers['authorization'] = 'Bearer $token';
  }

  // ------------------------------------------------------------------ LOGIN
  /// Logs in with email + password. Returns { token, supplierId, storeName }.
  Future<Map<String, dynamic>> login(String email, String password) async {
    await _init();
    await _jar.deleteAll();
    _dio.options.headers.remove('Authorization');
    _dio.options.headers.remove('authorization');

    Response res;
    try {
      res = await _dio.post(
        '/api/container/user/v2-login',
        data: {'email': email.trim(), 'password': password},
      );
    } on DioException catch (e) {
      throw MeeshoError('Network error: ${e.message ?? e.type.name}');
    }

    final body = _asMap(res.data);
    if (res.statusCode == 401 || res.statusCode == 403) {
      throw MeeshoError(_msgFrom(body) ?? 'Wrong email or password');
    }
    if (res.statusCode != 200) {
      throw MeeshoError(_msgFrom(body) ?? 'Login failed (${res.statusCode})');
    }

    // token can sit at several levels depending on the response shape
    final token = _firstString(body, const [
      'token', 'access_token', 'accessToken', 'id_token', 'idToken', 'jwt',
    ]);
    final cookies = await _jar.loadForRequest(Uri.parse(base));
    if (token == null && cookies.isEmpty) {
      final msg = _msgFrom(body);
      if (msg != null) throw MeeshoError(msg);
      throw MeeshoError('Login did not return a session. Meesho may be asking for OTP/captcha.');
    }
    _applyToken(token);

    String supplierId = _firstString(body, const ['supplier_id', 'supplierId']) ?? '';
    String storeName = _firstString(body, const ['name', 'supplier_name', 'business_name', 'shop_name']) ?? '';

    // fill in whatever the login response didn't give us
    if (supplierId.isEmpty || storeName.isEmpty) {
      try {
        final d = await supplierDetails();
        if (supplierId.isEmpty) supplierId = d['supplierId'] ?? '';
        if (storeName.isEmpty) storeName = d['storeName'] ?? '';
      } catch (_) {}
    }

    return {'token': token ?? '', 'supplierId': supplierId, 'storeName': storeName};
  }

  // ------------------------------------------------------- SUPPLIER DETAILS
  Future<Map<String, String>> supplierDetails() async {
    await _init();
    final res = await _dio.get('/api/container/supplier/getSupplierDetails');
    if (res.statusCode == 401 || res.statusCode == 403) throw SessionExpired();
    final body = _asMap(res.data);
    return {
      'supplierId': _firstString(body, const ['supplier_id', 'supplierId', 'id']) ?? '',
      'storeName': _firstString(body, const [
        'name', 'supplier_name', 'business_name', 'shop_name', 'display_name',
      ]) ?? '',
    };
  }

  // --------------------------------------------------------------- THE OTPs
  /// Fetches the return-delivery OTPs. Falls back through a few request shapes
  /// because Meesho has changed this endpoint's contract before.
  Future<List<OtpEntry>> fetchOtps({String? supplierId}) async {
    await _init();

    const path = '/api/fulfillment/returnRto/fetchDeliveryOTPs';
    final attempts = <Future<Response> Function()>[
      () => _dio.post(path, data: {
            if (supplierId != null && supplierId.isNotEmpty) 'supplier_id': int.tryParse(supplierId) ?? supplierId,
          }),
      () => _dio.post(path, data: {}),
      () => _dio.get(path),
    ];

    Response? ok;
    Object? lastErr;
    for (final attempt in attempts) {
      try {
        final res = await attempt();
        if (res.statusCode == 401 || res.statusCode == 403) throw SessionExpired();
        if (res.statusCode == 200 && res.data != null) { ok = res; break; }
        lastErr = 'HTTP ${res.statusCode}';
      } on SessionExpired {
        rethrow;
      } catch (e) {
        lastErr = e;
      }
    }
    if (ok == null) throw MeeshoError('Could not read OTPs ($lastErr)');

    final entries = parseOtps(ok.data);
    if (entries.isEmpty) {
      // keep the raw body so the user can send it to us if the shape changed
      lastRawResponse = _preview(ok.data);
    }
    return entries;
  }

  /// Last raw OTP response (trimmed) — shown in the app's debug sheet.
  static String? lastRawResponse;

  // ------------------------------------------------------------- PAYMENTS
  Future<Map<String, dynamic>> fetchPayments() async {
    await _init();
    try {
      final res = await _dio.post('/api/payouts/payments/all-ui-data2', data: {});
      if (res.statusCode == 401 || res.statusCode == 403) throw SessionExpired();
      if (res.statusCode != 200) return {};
      final body = _asMap(res.data);
      return {
        'upcoming': _firstNum(body, const [
          'upcoming_payment', 'upcomingPayment', 'total_amount', 'amount', 'upcoming_total_amount',
        ]),
        'nextDate': _firstString(body, const ['next_payment_date', 'payment_date', 'date']),
      };
    } catch (_) {
      return {};
    }
  }

  // ------------------------------------------------------------- PARSING
  /// Walks any JSON shape and pulls out every {carrier, otp, count} it can find.
  static List<OtpEntry> parseOtps(dynamic data) {
    final out = <OtpEntry>[];
    void walk(dynamic node, int depth) {
      if (depth > 10 || node == null) return;
      if (node is List) {
        for (final v in node) walk(v, depth + 1);
        return;
      }
      if (node is! Map) return;
      final map = node.map((k, v) => MapEntry(k.toString(), v));

      final otp = _pick(map, const [
        'otp_code', 'supplier_delivery_otp', 'delivery_otp', 'otp', 'end_otp',
        'return_otp', 'admin_lock_otp',
      ]);
      final carrier = _pick(map, const [
        'carrier', 'courier', 'carrier_name', 'courier_name', 'logistics_name',
        'logistics_partner', 'sp_name', 'name',
      ]);
      if (otp != null && carrier != null) {
        final otpStr = otp.toString().trim();
        final carrierStr = _cleanCarrier(carrier.toString());
        if (RegExp(r'^\d{3,8}$').hasMatch(otpStr) && carrierStr.isNotEmpty) {
          final count = _pick(map, const [
            'count', 'total_count', 'handover_count', 'total_handover_count',
            'shipment_count', 'shipments', 'awb_count',
          ]);
          final time = _pick(map, const [
            'otp_generated_at', 'created_at', 'generated_at', 'updated_at', 'time', 'date',
          ]);
          final key = '$carrierStr|$otpStr';
          if (!out.any((e) => '${e.carrier}|${e.otp}' == key)) {
            out.add(OtpEntry(
              carrier: carrierStr,
              otp: otpStr,
              count: _toInt(count),
              time: _formatTime(time),
            ));
          }
        }
      }
      for (final v in map.values) walk(v, depth + 1);
    }

    walk(data, 0);
    out.sort((a, b) => b.count.compareTo(a.count));
    return out;
  }

  static String _cleanCarrier(String s) {
    var v = s.trim().replaceAll(RegExp(r'\s+'), ' ');
    if (v.length > 30 || v.isEmpty) return '';
    if (RegExp(r'^\d+$').hasMatch(v)) return '';
    final lower = v.toLowerCase();
    const fix = {
      'xpress bees': 'Xpressbees',
      'xpressbees': 'Xpressbees',
      'delhivery': 'Delhivery',
      'shadowfax': 'Shadowfax',
      'valmo': 'Valmo',
      'ecom express': 'Ecom Express',
      'ekart': 'Ekart',
    };
    for (final e in fix.entries) {
      if (lower == e.key || lower.replaceAll('_', ' ') == e.key) return e.value;
    }
    return v.split(' ').map((w) => w.isEmpty ? w : w[0].toUpperCase() + w.substring(1)).join(' ');
  }

  static String _formatTime(dynamic v) {
    if (v == null) return '';
    final s = v.toString();
    final ms = int.tryParse(s);
    DateTime? dt;
    if (ms != null && s.length >= 10) {
      dt = DateTime.fromMillisecondsSinceEpoch(s.length > 11 ? ms : ms * 1000);
    } else {
      dt = DateTime.tryParse(s);
    }
    if (dt == null) return s.length > 24 ? '' : s;
    const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    final local = dt.toLocal();
    var h = local.hour % 12; if (h == 0) h = 12;
    final ap = local.hour < 12 ? 'AM' : 'PM';
    return '${local.day} ${months[local.month - 1]}, '
        '${h.toString().padLeft(2, '0')}:${local.minute.toString().padLeft(2, '0')} $ap';
  }

  static dynamic _pick(Map<String, dynamic> m, List<String> keys) {
    for (final k in keys) {
      for (final entry in m.entries) {
        if (entry.key.toLowerCase() == k && entry.value != null && entry.value is! Map && entry.value is! List) {
          return entry.value;
        }
      }
    }
    return null;
  }

  static int _toInt(dynamic v) {
    if (v == null) return 0;
    if (v is int) return v;
    if (v is double) return v.round();
    return int.tryParse(v.toString()) ?? 0;
  }

  static Map<String, dynamic> _asMap(dynamic d) {
    if (d is Map) return d.map((k, v) => MapEntry(k.toString(), v));
    if (d is String) {
      try { final p = jsonDecode(d); if (p is Map) return p.map((k, v) => MapEntry(k.toString(), v)); } catch (_) {}
    }
    return {};
  }

  static String? _firstString(dynamic node, List<String> keys, [int depth = 0]) {
    if (depth > 6 || node == null) return null;
    if (node is List) {
      for (final v in node) { final r = _firstString(v, keys, depth + 1); if (r != null) return r; }
      return null;
    }
    if (node is! Map) return null;
    for (final k in keys) {
      for (final e in node.entries) {
        if (e.key.toString().toLowerCase() == k.toLowerCase()) {
          final v = e.value;
          if (v != null && v is! Map && v is! List && v.toString().trim().isNotEmpty) return v.toString().trim();
        }
      }
    }
    for (final v in node.values) { final r = _firstString(v, keys, depth + 1); if (r != null) return r; }
    return null;
  }

  static num? _firstNum(dynamic node, List<String> keys) {
    final s = _firstString(node, keys);
    return s == null ? null : num.tryParse(s.replaceAll(RegExp(r'[^\d.\-]'), ''));
  }

  static String? _msgFrom(Map<String, dynamic> body) {
    final m = _firstString(body, const ['message', 'error', 'error_message', 'msg', 'detail']);
    if (m == null) return null;
    return m.length > 160 ? m.substring(0, 160) : m;
  }

  static String _preview(dynamic d) {
    try {
      final s = d is String ? d : jsonEncode(d);
      return s.length > 3000 ? '${s.substring(0, 3000)}…' : s;
    } catch (_) { return d.toString(); }
  }
}
