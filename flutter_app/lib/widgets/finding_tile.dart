import 'package:flutter/material.dart';
import '../models/scan_result.dart';

class FindingTile extends StatelessWidget {
  final Finding finding;
  final VoidCallback onTap;

  const FindingTile({
    super.key,
    required this.finding,
    required this.onTap,
  });

  Color _getSeverityColor() {
    switch (finding.severityLevel) {
      case SeverityLevel.high:
        return Colors.red;
      case SeverityLevel.medium:
        return Colors.orange;
      case SeverityLevel.low:
        return Colors.green;
    }
  }

  String _getSeverityLabel() {
    return finding.severity.toUpperCase();
  }

  IconData _getTriageIcon() {
    if (finding.triage == null) return Icons.help_outline;
    switch (finding.triage!.decision) {
      case 'true_positive':
        return Icons.dangerous;
      case 'false_positive':
        return Icons.check_circle;
      default:
        return Icons.pending;
    }
  }

  Color _getTriageColor() {
    if (finding.triage == null) return Colors.grey;
    switch (finding.triage!.decision) {
      case 'true_positive':
        return Colors.red;
      case 'false_positive':
        return Colors.green;
      default:
        return Colors.orange;
    }
  }

  @override
  Widget build(BuildContext context) {
    return ListTile(
      onTap: onTap,
      leading: Container(
        width: 40,
        height: 40,
        decoration: BoxDecoration(
          color: _getSeverityColor().withOpacity(0.2),
          borderRadius: BorderRadius.circular(8),
        ),
        child: Center(
          child: Text(
            _getSeverityLabel().substring(0, 1),
            style: TextStyle(
              color: _getSeverityColor(),
              fontWeight: FontWeight.bold,
            ),
          ),
        ),
      ),
      title: Text(
        finding.ruleId,
        style: const TextStyle(
          color: Colors.white,
          fontWeight: FontWeight.w500,
        ),
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
      ),
      subtitle: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SizedBox(height: 4),
          Text(
            finding.message,
            style: const TextStyle(color: Colors.grey, fontSize: 12),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
          const SizedBox(height: 4),
          Row(
            children: [
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                decoration: BoxDecoration(
                  color: _getSeverityColor().withOpacity(0.2),
                  borderRadius: BorderRadius.circular(4),
                ),
                child: Text(
                  _getSeverityLabel(),
                  style: TextStyle(
                    color: _getSeverityColor(),
                    fontSize: 10,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
              const SizedBox(width: 8),
              Icon(
                _getTriageIcon(),
                size: 14,
                color: _getTriageColor(),
              ),
              const SizedBox(width: 4),
              Text(
                '${finding.file}:${finding.line}',
                style: const TextStyle(color: Colors.grey, fontSize: 11),
              ),
            ],
          ),
        ],
      ),
      trailing: const Icon(
        Icons.chevron_right,
        color: Colors.grey,
      ),
    );
  }
}
