import 'dart:io';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:fl_chart/fl_chart.dart';
import 'package:intl/intl.dart';
import 'package:file_picker/file_picker.dart';
import '../models/scan_result.dart';
import '../services/api_service.dart';
import '../widgets/summary_card.dart';
import '../widgets/finding_tile.dart';
import 'finding_detail_screen.dart';

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  ScanResult? _scanResult;
  bool _isLoading = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _loadScanResult();
  }

  Future<void> _loadScanResult() async {
    setState(() {
      _isLoading = true;
      _error = null;
    });

    try {
      final api = context.read<ApiService>();
      final result = await api.getCurrentScan();
      setState(() {
        _scanResult = result;
        _isLoading = false;
      });
    } catch (e) {
      setState(() {
        _error = e.toString();
        _isLoading = false;
      });
    }
  }

  Future<void> _uploadFile() async {
    try {
      FilePickerResult? result = await FilePicker.platform.pickFiles(
        type: FileType.custom,
        allowedExtensions: ['json'],
        allowMultiple: false,
      );

      if (result != null) {
        final file = result.files.single;

        // Handle web platform (uses bytes instead of path)
        if (file.bytes != null) {
          // Web platform - upload using bytes
          final api = context.read<ApiService>();
          await api.uploadScanFileBytes(file.bytes!, file.name);
        } else if (file.path != null) {
          // Desktop/Mobile platform - upload using file path
          final fileObj = File(file.path!);
          final api = context.read<ApiService>();
          await api.uploadScanFile(fileObj);
        }

        _loadScanResult();

        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Scan results uploaded successfully'),
              backgroundColor: Colors.green,
            ),
          );
        }
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Upload failed: $e'),
            backgroundColor: Colors.red,
          ),
        );
      }
    }
  }

  Future<void> _clearScan() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Clear Scan Results'),
        content: const Text('Are you sure you want to clear the current scan results?'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            style: TextButton.styleFrom(foregroundColor: Colors.red),
            child: const Text('Clear'),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      try {
        final api = context.read<ApiService>();
        await api.clearScan();
        _loadScanResult();
      } catch (e) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Failed to clear: $e'),
              backgroundColor: Colors.red,
            ),
          );
        }
      }
    }
  }

  @override
  void dispose() {
    context.read<ApiService>().dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: _buildAppBar(),
      body: _buildBody(),
    );
  }

  PreferredSizeWidget _buildAppBar() {
    return AppBar(
      title: const Row(
        children: [
          Text('🔐 ', style: TextStyle(fontSize: 24)),
          Text('AI Security Scanner'),
        ],
      ),
      backgroundColor: const Color(0xFF1E293B),
      foregroundColor: Colors.white,
      elevation: 0,
      actions: [
        IconButton(
          icon: const Icon(Icons.refresh),
          onPressed: _loadScanResult,
          tooltip: 'Refresh',
        ),
        IconButton(
          icon: const Icon(Icons.delete_outline),
          onPressed: _clearScan,
          tooltip: 'Clear Results',
        ),
      ],
    );
  }

  Widget _buildBody() {
    if (_isLoading) {
      return const Center(child: CircularProgressIndicator());
    }

    if (_error != null) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.error_outline, size: 64, color: Colors.grey),
            const SizedBox(height: 16),
            Text(
              'Error loading scan results',
              style: Theme.of(context).textTheme.headlineSmall,
            ),
            const SizedBox(height: 8),
            Text(
              _error!,
              style: const TextStyle(color: Colors.grey),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 24),
            ElevatedButton.icon(
              onPressed: _uploadFile,
              icon: const Icon(Icons.upload_file),
              label: const Text('Upload Scan Results'),
            ),
          ],
        ),
      );
    }

    if (_scanResult == null) {
      return _buildEmptyState();
    }

    return _buildDashboard();
  }

  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const Icon(Icons.security, size: 80, color: Colors.grey),
          const SizedBox(height: 24),
          Text(
            'No Scan Results Loaded',
            style: Theme.of(context).textTheme.headlineMedium,
          ),
          const SizedBox(height: 8),
          const Text(
            'Upload a security scan report to view results',
            style: TextStyle(color: Colors.grey),
          ),
          const SizedBox(height: 32),
          ElevatedButton.icon(
            onPressed: _uploadFile,
            icon: const Icon(Icons.upload_file),
            label: const Text('Upload Scan Results'),
            style: ElevatedButton.styleFrom(
              padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 16),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildDashboard() {
    return RefreshIndicator(
      onRefresh: _loadScanResult,
      child: SingleChildScrollView(
        physics: const AlwaysScrollableScrollPhysics(),
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _buildScanInfo(),
            const SizedBox(height: 24),
            _buildSummaryCards(),
            const SizedBox(height: 24),
            _buildCharts(),
            const SizedBox(height: 24),
            _buildFindingsSection(),
          ],
        ),
      ),
    );
  }

  Widget _buildScanInfo() {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF1E293B),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Scan: ${_scanResult!.targetPath.split('/').last}',
                style: const TextStyle(
                  color: Colors.white,
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 4),
              Text(
                DateFormat('yyyy-MM-dd HH:mm').format(
                  DateTime.tryParse(_scanResult!.scanTime) ?? DateTime.now(),
                ),
                style: const TextStyle(color: Colors.grey),
              ),
            ],
          ),
          ElevatedButton.icon(
            onPressed: _uploadFile,
            icon: const Icon(Icons.upload_file),
            label: const Text('Upload New'),
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFF6366F1),
              foregroundColor: Colors.white,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSummaryCards() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'Summary',
          style: TextStyle(
            fontSize: 20,
            fontWeight: FontWeight.bold,
            color: Colors.white,
          ),
        ),
        const SizedBox(height: 12),
        GridView.count(
          shrinkWrap: true,
          physics: const NeverScrollableScrollPhysics(),
          crossAxisCount: MediaQuery.of(context).size.width > 600 ? 4 : 2,
          mainAxisSpacing: 12,
          crossAxisSpacing: 12,
          childAspectRatio: 1.5,
          children: [
            SummaryCard(
              title: 'Total Findings',
              count: _scanResult!.summary.totalFindings,
              icon: Icons.analytics,
              color: const Color(0xFF6366F1),
            ),
            SummaryCard(
              title: 'Confirmed',
              count: _scanResult!.summary.confirmedVulnerabilities,
              icon: Icons.dangerous,
              color: Colors.red,
            ),
            SummaryCard(
              title: 'False Positives',
              count: _scanResult!.summary.falsePositives,
              icon: Icons.check_circle,
              color: Colors.green,
            ),
            SummaryCard(
              title: 'Needs Review',
              count: _scanResult!.summary.needsReview,
              icon: Icons.pending,
              color: Colors.orange,
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildCharts() {
    final width = MediaQuery.of(context).size.width;
    final isWide = width > 800;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'Analysis',
          style: TextStyle(
            fontSize: 20,
            fontWeight: FontWeight.bold,
            color: Colors.white,
          ),
        ),
        const SizedBox(height: 12),
        isWide
            ? Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Expanded(child: _buildSeverityChart()),
                  const SizedBox(width: 16),
                  Expanded(child: _buildTriageChart()),
                ],
              )
            : Column(
                children: [
                  _buildSeverityChart(),
                  const SizedBox(height: 16),
                  _buildTriageChart(),
                ],
              ),
      ],
    );
  }

  Widget _buildSeverityChart() {
    final severityCounts = _calculateSeverityCounts();

    return Card(
      color: const Color(0xFF1E293B),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            const Text(
              'By Severity',
              style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 16),
            SizedBox(
              height: 200,
              child: PieChart(
                PieChartData(
                  sections: [
                    PieChartSectionData(
                      value: severityCounts['high']?.toDouble() ?? 0,
                      color: Colors.red,
                      title: 'High\n${severityCounts['high']}',
                      radius: 60,
                      titleStyle: const TextStyle(
                        color: Colors.white,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    PieChartSectionData(
                      value: severityCounts['medium']?.toDouble() ?? 0,
                      color: Colors.orange,
                      title: 'Medium\n${severityCounts['medium']}',
                      radius: 60,
                      titleStyle: const TextStyle(
                        color: Colors.white,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    PieChartSectionData(
                      value: severityCounts['low']?.toDouble() ?? 0,
                      color: Colors.green,
                      title: 'Low\n${severityCounts['low']}',
                      radius: 60,
                      titleStyle: const TextStyle(
                        color: Colors.white,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ],
                  sectionsSpace: 2,
                  centerSpaceRadius: 40,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildTriageChart() {
    return Card(
      color: const Color(0xFF1E293B),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            const Text(
              'Triage Status',
              style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 16),
            SizedBox(
              height: 200,
              child: PieChart(
                PieChartData(
                  sections: [
                    PieChartSectionData(
                      value: _scanResult!.summary.confirmedVulnerabilities.toDouble(),
                      color: Colors.red,
                      title: 'True\nPositive',
                      radius: 60,
                      titleStyle: const TextStyle(
                        color: Colors.white,
                        fontWeight: FontWeight.bold,
                        fontSize: 10,
                      ),
                    ),
                    PieChartSectionData(
                      value: _scanResult!.summary.falsePositives.toDouble(),
                      color: Colors.green,
                      title: 'False\nPositive',
                      radius: 60,
                      titleStyle: const TextStyle(
                        color: Colors.white,
                        fontWeight: FontWeight.bold,
                        fontSize: 10,
                      ),
                    ),
                    PieChartSectionData(
                      value: _scanResult!.summary.needsReview.toDouble(),
                      color: Colors.orange,
                      title: 'Needs\nReview',
                      radius: 60,
                      titleStyle: const TextStyle(
                        color: Colors.white,
                        fontWeight: FontWeight.bold,
                        fontSize: 10,
                      ),
                    ),
                  ],
                  sectionsSpace: 2,
                  centerSpaceRadius: 40,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Map<String, int> _calculateSeverityCounts() {
    final counts = <String, int>{'high': 0, 'medium': 0, 'low': 0};

    for (final finding in _scanResult!.findings) {
      switch (finding.severityLevel) {
        case SeverityLevel.high:
          counts['high'] = (counts['high'] ?? 0) + 1;
          break;
        case SeverityLevel.medium:
          counts['medium'] = (counts['medium'] ?? 0) + 1;
          break;
        case SeverityLevel.low:
          counts['low'] = (counts['low'] ?? 0) + 1;
          break;
      }
    }

    return counts;
  }

  Widget _buildFindingsSection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'Findings',
          style: TextStyle(
            fontSize: 20,
            fontWeight: FontWeight.bold,
            color: Colors.white,
          ),
        ),
        const SizedBox(height: 12),
        Card(
          color: const Color(0xFF1E293B),
          child: ListView.separated(
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            itemCount: _scanResult!.findings.length,
            separatorBuilder: (context, index) => const Divider(height: 1),
            itemBuilder: (context, index) {
              final finding = _scanResult!.findings[index];
              return FindingTile(
                finding: finding,
                onTap: () {
                  Navigator.push(
                    context,
                    MaterialPageRoute(
                      builder: (context) => FindingDetailScreen(
                        finding: finding,
                        index: index,
                        total: _scanResult!.findings.length,
                      ),
                    ),
                  );
                },
              );
            },
          ),
        ),
      ],
    );
  }
}
