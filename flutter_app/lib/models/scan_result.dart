
class ScanResult {
  final String scanTime;
  final String targetPath;
  final Summary summary;
  final List<Finding> findings;

  ScanResult({
    required this.scanTime,
    required this.targetPath,
    required this.summary,
    required this.findings,
  });

  factory ScanResult.fromJson(Map<String, dynamic> json) {
    return ScanResult(
      scanTime: json['scan_time'] ?? '',
      targetPath: json['target_path'] ?? '',
      summary: Summary.fromJson(json['summary'] ?? {}),
      findings: (json['findings'] as List<dynamic>?)
              ?.map((f) => Finding.fromJson(f))
              .toList() ??
          [],
    );
  }

  Map<String, dynamic> toJson() => {
        'scan_time': scanTime,
        'target_path': targetPath,
        'summary': summary.toJson(),
        'findings': findings.map((f) => f.toJson()).toList(),
      };
}

class Summary {
  final int totalFindings;
  final int confirmedVulnerabilities;
  final int falsePositives;
  final int needsReview;

  Summary({
    required this.totalFindings,
    required this.confirmedVulnerabilities,
    required this.falsePositives,
    required this.needsReview,
  });

  factory Summary.fromJson(Map<String, dynamic> json) {
    return Summary(
      totalFindings: json['total_findings'] ?? 0,
      confirmedVulnerabilities: json['confirmed_vulnerabilities'] ?? 0,
      falsePositives: json['false_positives'] ?? 0,
      needsReview: json['needs_review'] ?? 0,
    );
  }

  Map<String, dynamic> toJson() => {
        'total_findings': totalFindings,
        'confirmed_vulnerabilities': confirmedVulnerabilities,
        'false_positives': falsePositives,
        'needs_review': needsReview,
      };
}

class Finding {
  final String ruleId;
  final String message;
  final String file;
  final int line;
  final String severity;
  final String codeSnippet;
  final Triage? triage;
  final Fix? fix;

  Finding({
    required this.ruleId,
    required this.message,
    required this.file,
    required this.line,
    required this.severity,
    this.codeSnippet = '',
    this.triage,
    this.fix,
  });

  factory Finding.fromJson(Map<String, dynamic> json) {
    return Finding(
      ruleId: json['rule_id'] ?? '',
      message: json['message'] ?? '',
      file: json['file'] ?? '',
      line: json['line'] ?? 0,
      severity: json['severity'] ?? 'WARNING',
      codeSnippet: json['code_snippet'] ?? '',
      triage: json['triage'] != null ? Triage.fromJson(json['triage']) : null,
      fix: json['fix'] != null ? Fix.fromJson(json['fix']) : null,
    );
  }

  Map<String, dynamic> toJson() => {
        'rule_id': ruleId,
        'message': message,
        'file': file,
        'line': line,
        'severity': severity,
        'code_snippet': codeSnippet,
        'triage': triage?.toJson(),
        'fix': fix?.toJson(),
      };

  SeverityLevel get severityLevel {
    switch (severity.toLowerCase()) {
      case 'critical':
      case 'error':
        return SeverityLevel.high;
      case 'warning':
        return SeverityLevel.medium;
      default:
        return SeverityLevel.low;
    }
  }
}

enum SeverityLevel { high, medium, low }

class Triage {
  final String decision;
  final String confidence;
  final String explanation;
  final String? exploitScenario;
  final String? recommendedAction;

  Triage({
    required this.decision,
    required this.confidence,
    required this.explanation,
    this.exploitScenario,
    this.recommendedAction,
  });

  factory Triage.fromJson(Map<String, dynamic> json) {
    return Triage(
      decision: json['decision'] ?? '',
      confidence: json['confidence'] ?? 'medium',
      explanation: json['explanation'] ?? '',
      exploitScenario: json['exploit_scenario'],
      recommendedAction: json['recommended_action'],
    );
  }

  Map<String, dynamic> toJson() => {
        'decision': decision,
        'confidence': confidence,
        'explanation': explanation,
        'exploit_scenario': exploitScenario,
        'recommended_action': recommendedAction,
      };
}

class Fix {
  final String originalCode;
  final String fixedCode;
  final String explanation;
  final String diffSummary;
  final String confidence;

  Fix({
    required this.originalCode,
    required this.fixedCode,
    required this.explanation,
    required this.diffSummary,
    required this.confidence,
  });

  factory Fix.fromJson(Map<String, dynamic> json) {
    return Fix(
      originalCode: json['original_code'] ?? '',
      fixedCode: json['fixed_code'] ?? '',
      explanation: json['explanation'] ?? '',
      diffSummary: json['diff_summary'] ?? '',
      confidence: json['confidence'] ?? 'medium',
    );
  }

  Map<String, dynamic> toJson() => {
        'original_code': originalCode,
        'fixed_code': fixedCode,
        'explanation': explanation,
        'diff_summary': diffSummary,
        'confidence': confidence,
      };
}
