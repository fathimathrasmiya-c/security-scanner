import React, { useState, useEffect, useCallback } from 'react'
import {
  Shield,
  Upload,
  RefreshCw,
  Search,
  FileWarning,
  AlertTriangle,
  CheckCircle,
  AlertCircle
} from 'lucide-react'
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts'

const COLORS = {
  high: '#f87171',
  medium: '#fbbf24',
  low: '#4ade80',
}

function App() {
  const [scanData, setScanData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [severityFilter, setSeverityFilter] = useState('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [fileName, setFileName] = useState('')

  const loadScanData = useCallback(() => {
    setLoading(true)
    setTimeout(() => {
      try {
        const saved = localStorage.getItem('scanData')
        const savedName = localStorage.getItem('scanFileName')
        if (saved) {
          setScanData(JSON.parse(saved))
          setFileName(savedName || 'Last Uploaded File')
        } else {
          setScanData(null)
          setFileName('')
        }
      } catch (err) {
        console.error('Error loading saved data:', err)
      } finally {
        setLoading(false)
      }
    }, 300) // Brief delay to show visual feedback
  }, [])

  useEffect(() => {
    loadScanData()
  }, [loadScanData])

  const handleFileUpload = (event) => {
    const file = event.target.files[0]
    if (!file) return

    setFileName(file.name)
    localStorage.setItem('scanFileName', file.name)

    const reader = new FileReader()

    reader.onload = (e) => {
      try {
        const data = JSON.parse(e.target.result)
        console.log('Uploaded JSON:', data)
        setScanData(data)
        localStorage.setItem('scanData', JSON.stringify(data))
      } catch (error) {
        alert('Invalid JSON file!')
        console.error(error)
      }
      
      // Reset the input value so the onChange event triggers again even for the same file
      event.target.value = ''
    }

    reader.readAsText(file)
  }

  const handleClearScan = () => {
    localStorage.removeItem('scanData')
    localStorage.removeItem('scanFileName')
    setScanData(null)
    setFileName('')
  }

  const getSeverityCounts = () => {
    if (!scanData) return { high: 0, medium: 0, low: 0 }

    const counts = { high: 0, medium: 0, low: 0 }
    const items = scanData.findings || scanData.vulnerabilities || []
    items.forEach(finding => {
      const severity = finding.severity?.toLowerCase()
      if (severity === 'critical' || severity === 'error') counts.high++
      else if (severity === 'warning') counts.medium++
      else counts.low++
    })
    return counts
  }

  const getTriageData = () => {
    if (!scanData) return []

    return [
      { name: 'True Positive', value: scanData.summary?.confirmed_vulnerabilities || 0, color: '#f87171' },
      { name: 'False Positive', value: scanData.summary?.false_positives || 0, color: '#4ade80' },
      { name: 'Needs Review', value: scanData.summary?.needs_review || 0, color: '#fbbf24' },
    ].filter(item => item.value > 0)
  }

  const getFilteredFindings = () => {
    if (!scanData) return []

    let findings = scanData.findings || scanData.vulnerabilities || []

    if (severityFilter !== 'all') {
      findings = findings.filter(f => {
        const severity = f.severity?.toLowerCase()
        if (severityFilter === 'high') return severity === 'critical' || severity === 'error'
        if (severityFilter === 'medium') return severity === 'warning'
        if (severityFilter === 'low') return severity === 'info'
        return true
      })
    }

    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      findings = findings.filter(f =>
        f.file?.toLowerCase().includes(query) ||
        f.message?.toLowerCase().includes(query) ||
        f.rule_id?.toLowerCase().includes(query)
      )
    }

    return findings
  }

  const getSeverityLevel = (severity) => {
    const s = severity?.toLowerCase()
    if (s === 'critical' || s === 'error') return 'high'
    if (s === 'warning') return 'medium'
    return 'low'
  }

  const severityCounts = getSeverityCounts()
  const severityData = [
    { name: 'High', value: severityCounts.high, color: COLORS.high },
    { name: 'Medium', value: severityCounts.medium, color: COLORS.medium },
    { name: 'Low', value: severityCounts.low, color: COLORS.low },
  ].filter(item => item.value > 0)

  const triageData = getTriageData()
  const filteredFindings = getFilteredFindings()

  if (loading) {
    return (
      <div className="dashboard">
        <div className="loading">
          <div className="spinner"></div>
        </div>
      </div>
    )
  }

  return (
    <div className="dashboard">
      {/* Header */}
      <div className="dashboard-header">
        <div>
          <h1>
            <Shield size={32} />
            Security Scan Dashboard
          </h1>
          {fileName && <p style={{ margin: 0, color: '#94a3b8', fontSize: '0.9rem', marginTop: '4px' }}>Uploaded File: {fileName}</p>}
        </div>
        <div className="header-actions">
          <button type="button" className="btn btn-outline" onClick={loadScanData}>
            <RefreshCw size={16} />
            Refresh
          </button>
          <label className="btn btn-primary">
            <Upload size={16} />
            Upload Scan
            <input
              type="file"
              accept=".json"
              onChange={handleFileUpload}
              className="file-input"
            />
          </label>
          {scanData && (
            <button type="button" className="btn btn-outline" onClick={handleClearScan}>
              Clear
            </button>
          )}
        </div>
      </div>

      {!scanData ? (
        /* Empty State */
        <div className="empty-state">
          <div className="empty-icon">🔍</div>
          <h2>No Scan Results Loaded</h2>
          <p>Upload a security scan report (report.json) to view results</p>
          <label className="btn btn-primary" style={{ display: 'inline-flex' }}>
            <Upload size={16} />
            Upload Scan Results
            <input
              type="file"
              accept=".json"
              onChange={handleFileUpload}
              className="file-input"
            />
          </label>
        </div>
      ) : (
        <>
          {/* Summary Cards */}
          <div className="summary-grid">
            <div className="summary-card">
              <div className="summary-icon total">📊</div>
              <div className="summary-content">
                <div className="summary-label">Total Issues</div>
                <div className="summary-value total">{scanData.summary?.total_findings || 0}</div>
              </div>
            </div>
            <div className="summary-card">
              <div className="summary-icon high">⚠️</div>
              <div className="summary-content">
                <div className="summary-label">High Severity</div>
                <div className="summary-value high">{severityCounts.high}</div>
              </div>
            </div>
            <div className="summary-card">
              <div className="summary-icon medium">⚡</div>
              <div className="summary-content">
                <div className="summary-label">Medium Severity</div>
                <div className="summary-value medium">{severityCounts.medium}</div>
              </div>
            </div>
            <div className="summary-card">
              <div className="summary-icon low">✅</div>
              <div className="summary-content">
                <div className="summary-label">Low Severity</div>
                <div className="summary-value low">{severityCounts.low}</div>
              </div>
            </div>
          </div>

          {/* Charts */}
          <div className="charts-section">
            <div className="chart-card">
              <h3>Issues by Severity</h3>
              <div style={{ height: 250 }}>
                {severityData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={severityData}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={80}
                        paddingAngle={2}
                        dataKey="value"
                        label={({ name, value }) => `${name}\n${value}`}
                        labelLine={false}
                      >
                        {severityData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#1e293b',
                          border: '1px solid #334155',
                          borderRadius: '8px',
                        }}
                      />
                      <Legend />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%', color: '#64748b' }}>
                    No severity data
                  </div>
                )}
              </div>
            </div>

            <div className="chart-card">
              <h3>AI Triage Results</h3>
              <div style={{ height: 250 }}>
                {triageData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={triageData}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={80}
                        paddingAngle={2}
                        dataKey="value"
                        label={({ name, value }) => `${name}\n${value}`}
                        labelLine={false}
                      >
                        {triageData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#1e293b',
                          border: '1px solid #334155',
                          borderRadius: '8px',
                        }}
                      />
                      <Legend />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%', color: '#64748b' }}>
                    No triage data
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Filters */}
          <div className="filters-section">
            <div className="filters-left">
              <span className="filter-label">Filter:</span>
              <select
                className="filter-select"
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
              >
                <option value="all">All Severities</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
            <div className="filters-right">
              <input
                type="text"
                className="search-input"
                placeholder="Search by file, issue, or rule..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
          </div>

          {/* Issues Table */}
          <div className="issues-table-container">
            <table className="issues-table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>File</th>
                  <th>Line</th>
                  <th>Issue</th>
                  <th>Rule ID</th>
                </tr>
              </thead>
              <tbody>
                {filteredFindings.length > 0 ? (
                  filteredFindings.map((finding, index) => (
                    <tr key={index}>
                      <td>
                        <span className={`severity-badge ${getSeverityLevel(finding.severity)}`}>
                          {getSeverityLevel(finding.severity)}
                        </span>
                      </td>
                      <td className="file-path">{finding.file}</td>
                      <td className="file-path">{finding.start?.line || finding.line || '-'}</td>
                      <td className="issue-message" title={finding.message}>
                        {finding.message || finding.extra?.message}
                      </td>
                      <td>
                        <span className="rule-id">{finding.rule_id || finding.check_id || '-'}</span>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="5" style={{ textAlign: 'center', padding: '40px', color: '#64748b' }}>
                      {searchQuery || severityFilter !== 'all'
                        ? 'No findings match your filters'
                        : 'No findings to display'}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  )
}

export default App
