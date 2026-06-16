import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../models/scan_result.dart';

class FindingDetailScreen extends StatefulWidget {
  final List<Finding> findings;
  final int initialIndex;

  const FindingDetailScreen({
    super.key,
    required this.findings,
    required this.initialIndex,
  });

  @override
  State<FindingDetailScreen> createState() => _FindingDetailScreenState();
}

class _FindingDetailScreenState extends State<FindingDetailScreen> {
  late int _currentIndex;

  @override
  void initState() {
    super.initState();
    _currentIndex = widget.initialIndex;
  }

  Finding get _currentFinding => widget.findings[_currentIndex];

  Color _getSeverityColor() {
    switch (_currentFinding.severityLevel) {
      case SeverityLevel.high:
        return Colors.red;
      case SeverityLevel.medium:
        return Colors.orange;
      case SeverityLevel.low:
        return Colors.green;
    }
  }

  void _goToPrevious() {
    if (_currentIndex > 0) {
      setState(() {
        _currentIndex--;
      });
    }
  }

  void _goToNext() {
    if (_currentIndex < widget.findings.length - 1) {
      setState(() {
        _currentIndex++;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('Finding #${_currentIndex + 1}'),
        backgroundColor: const Color(0xFF1E293B),
        foregroundColor: Colors.white,
        elevation: 0,
        actions: [
          IconButton(
            icon: const Icon(Icons.copy),
            onPressed: () => _copyToClipboard(context),
            tooltip: 'Copy Details',
          ),
          IconButton(
            icon: const Icon(Icons.chevron_left),
            onPressed: _currentIndex > 0 ? _goToPrevious : null,
            tooltip: 'Previous',
          ),
          IconButton(
            icon: const Icon(Icons.chevron_right),
            onPressed: _currentIndex < widget.findings.length - 1 ? _goToNext : null,
            tooltip: 'Next',
          ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _buildHeader(context),
            const SizedBox(height: 16),
            _buildInfoGrid(context),
            if (_currentFinding.triage != null) ...[
              const SizedBox(height: 16),
              _buildTriageSection(context),
            ],
            const SizedBox(height: 16),
            _buildCodeSection(context),
            if (_currentFinding.fix != null) ...[
              const SizedBox(height: 16),
              _buildFixSection(context),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildHeader(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF1E293B),
        borderRadius: BorderRadius.circular(12),
        border: Border(
          left: BorderSide(
            color: _getSeverityColor(),
            width: 4,
          ),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                decoration: BoxDecoration(
                  color: _getSeverityColor().withOpacity(0.2),
                  borderRadius: BorderRadius.circular(4),
                ),
                child: Text(
                  _currentFinding.severity.toUpperCase(),
                  style: TextStyle(
                    color: _getSeverityColor(),
                    fontWeight: FontWeight.bold,
                    fontSize: 12,
                  ),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Text(
                  _currentFinding.ruleId,
                  style: const TextStyle(
                    color: Colors.white,
                    fontWeight: FontWeight.bold,
                    fontSize: 16,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            _currentFinding.message,
            style: const TextStyle(color: Colors.grey),
          ),
        ],
      ),
    );
  }

  Widget _buildInfoGrid(BuildContext context) {
    final metadata = _currentFinding.metadata;
    final owasp = metadata['owasp'] ?? 'N/A';
    final cwe = metadata['cwe'] ?? 'N/A';

    return GridView.count(
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      crossAxisCount: 2,
      mainAxisSpacing: 12,
      crossAxisSpacing: 12,
      childAspectRatio: 2,
      children: [
        _buildInfoCard('File', _currentFinding.file),
        _buildInfoCard('Line', '${_currentFinding.line}:${_currentFinding.column}'),
        _buildInfoCard('OWASP', owasp),
        _buildInfoCard('CWE', cwe),
      ],
    );
  }

  Widget _buildInfoCard(String label, String value) {
    return Card(
      color: const Color(0xFF1E293B),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Text(
              label,
              style: const TextStyle(color: Colors.grey, fontSize: 11),
            ),
            const SizedBox(height: 4),
            Text(
              value,
              style: const TextStyle(
                color: Colors.white,
                fontWeight: FontWeight.w500,
              ),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildTriageSection(BuildContext context) {
    final triage = _currentFinding.triage!;

    return Card(
      color: const Color(0xFF1E293B),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  triage.decision == 'true_positive'
                      ? Icons.dangerous
                      : triage.decision == 'false_positive'
                          ? Icons.check_circle
                          : Icons.pending,
                  color: triage.decision == 'true_positive'
                      ? Colors.red
                      : triage.decision == 'false_positive'
                          ? Colors.green
                          : Colors.orange,
                ),
                const SizedBox(width: 8),
                const Text(
                  'AI Triage Result',
                  style: TextStyle(
                    color: Colors.white,
                    fontWeight: FontWeight.bold,
                    fontSize: 16,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 16),
            Row(
              children: [
                _buildTriageBadge('Decision', triage.decision.replaceAll('_', ' ')),
                const SizedBox(width: 8),
                _buildTriageBadge('Confidence', triage.confidence),
              ],
            ),
            const SizedBox(height: 16),
            _buildDetailBlock('Explanation', triage.explanation),
            if (triage.exploitScenario != null && triage.exploitScenario != 'N/A') ...[
              const SizedBox(height: 12),
              _buildDetailBlock('⚠️ Exploit Scenario', triage.exploitScenario!, isWarning: true),
            ],
            if (triage.recommendedAction != null) ...[
              const SizedBox(height: 12),
              _buildDetailBlock('✅ Recommended Action', triage.recommendedAction!, isSuccess: true),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildTriageBadge(String label, String value) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        color: const Color(0xFF334155),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            label,
            style: const TextStyle(color: Colors.grey, fontSize: 10),
          ),
          const SizedBox(height: 2),
          Text(
            value.toUpperCase(),
            style: const TextStyle(
              color: Colors.white,
              fontWeight: FontWeight.bold,
              fontSize: 12,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildDetailBlock(String title, String content, {bool isWarning = false, bool isSuccess = false}) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: const Color(0xFF334155),
        borderRadius: BorderRadius.circular(8),
        border: Border(
          left: BorderSide(
            color: isWarning ? Colors.orange : isSuccess ? Colors.green : const Color(0xFF6366F1),
            width: 3,
          ),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title,
            style: const TextStyle(
              color: Colors.grey,
              fontSize: 12,
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            content,
            style: const TextStyle(color: Colors.white),
          ),
        ],
      ),
    );
  }

  Widget _buildCodeSection(BuildContext context) {
    return Card(
      color: const Color(0xFF1E293B),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Vulnerable Code',
              style: TextStyle(
                color: Colors.white,
                fontWeight: FontWeight.bold,
                fontSize: 16,
              ),
            ),
            const SizedBox(height: 12),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.black.withOpacity(0.3),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: Colors.red.withOpacity(0.3)),
              ),
              child: SingleChildScrollView(
                scrollDirection: Axis.horizontal,
                child: Text(
                  _currentFinding.codeSnippet,
                  style: const TextStyle(
                    fontFamily: 'monospace',
                    color: Colors.red,
                    fontSize: 12,
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildFixSection(BuildContext context) {
    final fix = _currentFinding.fix!;

    return Card(
      color: const Color(0xFF1E293B),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              '🔧 Suggested Fix',
              style: TextStyle(
                color: Colors.white,
                fontWeight: FontWeight.bold,
                fontSize: 16,
              ),
            ),
            const SizedBox(height: 12),
            Text(
              fix.explanation,
              style: const TextStyle(color: Colors.grey),
            ),
            const SizedBox(height: 16),
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Expanded(
                  child: Column(
                    children: [
                      const Text(
                        'Before',
                        style: TextStyle(color: Colors.red, fontSize: 12),
                      ),
                      const SizedBox(height: 8),
                      Container(
                        padding: const EdgeInsets.all(12),
                        decoration: BoxDecoration(
                          color: Colors.red.withOpacity(0.1),
                          borderRadius: BorderRadius.circular(8),
                        ),
                        child: SingleChildScrollView(
                          scrollDirection: Axis.horizontal,
                          child: Text(
                            fix.originalCode,
                            style: const TextStyle(
                              fontFamily: 'monospace',
                              color: Colors.red,
                              fontSize: 11,
                            ),
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    children: [
                      const Text(
                        'After',
                        style: TextStyle(color: Colors.green, fontSize: 12),
                      ),
                      const SizedBox(height: 8),
                      Container(
                        padding: const EdgeInsets.all(12),
                        decoration: BoxDecoration(
                          color: Colors.green.withOpacity(0.1),
                          borderRadius: BorderRadius.circular(8),
                        ),
                        child: SingleChildScrollView(
                          scrollDirection: Axis.horizontal,
                          child: Text(
                            fix.fixedCode,
                            style: const TextStyle(
                              fontFamily: 'monospace',
                              color: Colors.green,
                              fontSize: 11,
                            ),
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  void _copyToClipboard(BuildContext context) {
    final text = '''
Finding: ${_currentFinding.ruleId}
Severity: ${_currentFinding.severity}
File: ${_currentFinding.file}:${_currentFinding.line}:${_currentFinding.column}
Message: ${_currentFinding.message}
${_currentFinding.triage != null ? 'Triage: ${_currentFinding.triage!.decision} (${_currentFinding.triage!.confidence})\nExplanation: ${_currentFinding.triage!.explanation}' : ''}
'''.trim();

    Clipboard.setData(ClipboardData(text: text));
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('Finding details copied to clipboard'),
        backgroundColor: Colors.green,
        duration: Duration(seconds: 2),
      ),
    );
  }
}
