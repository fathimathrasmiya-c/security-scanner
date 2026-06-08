import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:http/http.dart' as http;
import 'package:file_picker/file_picker.dart';
import '../models/scan_result.dart';

class ApiService {
  final String baseUrl;
  final http.Client _client;

  ApiService({this.baseUrl = 'http://127.0.0.1:5000'})
      : _client = http.Client();

  Future<ScanResult?> getCurrentScan() async {
    try {
      final response = await _client.get(
        Uri.parse('$baseUrl/api/scan/current'),
      );

      if (response.statusCode == 200) {
        return ScanResult.fromJson(json.decode(response.body));
      }
      return null;
    } catch (e) {
      throw Exception('Failed to fetch scan results: $e');
    }
  }

  Future<ScanResult> uploadScanFile(File file) async {
    try {
      var request = http.MultipartRequest(
        'POST',
        Uri.parse('$baseUrl/api/scan/file'),
      );
      request.files.add(await http.MultipartFile.fromPath('file', file.path));

      var response = await request.send();

      if (response.statusCode == 200) {
        final result = await getCurrentScan();
        if (result == null) {
          throw Exception('Upload succeeded but failed to fetch scan results');
        }
        return result;
      } else {
        throw Exception('Upload failed: ${response.reasonPhrase}');
      }
    } catch (e) {
      throw Exception('Failed to upload file: $e');
    }
  }

  Future<ScanResult> uploadScanFileBytes(Uint8List bytes, String fileName) async {
    try {
      var request = http.MultipartRequest(
        'POST',
        Uri.parse('$baseUrl/api/scan/file'),
      );
      request.files.add(http.MultipartFile.fromBytes(
        'file',
        bytes,
        filename: fileName,
      ));

      var response = await request.send();

      if (response.statusCode == 200) {
        final result = await getCurrentScan();
        if (result == null) {
          throw Exception('Upload succeeded but failed to fetch scan results');
        }
        return result;
      } else {
        throw Exception('Upload failed: ${response.reasonPhrase}');
      }
    } catch (e) {
      throw Exception('Failed to upload file: $e');
    }
  }

  Future<Map<String, dynamic>?> pickAndUploadFile() async {
    try {
      FilePickerResult? result = await FilePicker.platform.pickFiles(
        type: FileType.custom,
        allowedExtensions: ['json'],
      );

      if (result != null && result.files.single.path != null) {
        final file = File(result.files.single.path!);
        final scanResult = await uploadScanFile(file);
        return {
          'success': true,
          'data': scanResult,
        };
      }
      return null;
    } catch (e) {
      return {
        'success': false,
        'error': e.toString(),
      };
    }
  }

  Future<bool> clearScan() async {
    try {
      final response = await _client.post(
        Uri.parse('$baseUrl/api/scan/clear'),
      );

      if (response.statusCode == 200) {
        return true;
      }
      return false;
    } catch (e) {
      throw Exception('Failed to clear scan: $e');
    }
  }

  Future<List<Map<String, dynamic>>> getScanHistory() async {
    try {
      final response = await _client.get(
        Uri.parse('$baseUrl/api/scan/history'),
      );

      if (response.statusCode == 200) {
        return List<Map<String, dynamic>>.from(json.decode(response.body));
      }
      return [];
    } catch (e) {
      throw Exception('Failed to fetch history: $e');
    }
  }

  void dispose() {
    _client.close();
  }
}
