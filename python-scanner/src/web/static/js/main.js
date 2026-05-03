/**
 * AI Security Scanner Dashboard - Main JavaScript
 */

// Utility functions
function formatDateTime(isoString) {
    const date = new Date(isoString);
    return date.toLocaleString();
}

function formatSeverity(severity) {
    const colors = {
        'critical': '#dc2626',
        'error': '#dc2626',
        'warning': '#f59e0b',
        'info': '#06b6d4'
    };
    return colors[severity.toLowerCase()] || '#64748b';
}

// API helpers
async function fetchScanResults() {
    try {
        const response = await fetch('/api/scan/current');
        if (!response.ok) throw new Error('No scan results');
        return await response.json();
    } catch (error) {
        console.error('Failed to fetch scan results:', error);
        return null;
    }
}

async function fetchScanHistory() {
    try {
        const response = await fetch('/api/scan/history');
        return await response.json();
    } catch (error) {
        console.error('Failed to fetch history:', error);
        return [];
    }
}

async function uploadScanFile(file) {
    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch('/api/scan/file', {
        method: 'POST',
        body: formData
    });

    return await response.json();
}

async function clearScanResults() {
    const response = await fetch('/api/scan/clear', { method: 'POST' });
    return await response.json();
}

// Chart helpers
function createSeverityChart(ctx, data) {
    return new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'Error', 'Warning', 'Info'],
            datasets: [{
                data: data,
                backgroundColor: ['#dc2626', '#dc2626', '#f59e0b', '#06b6d4'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#94a3b8',
                        padding: 15
                    }
                }
            },
            cutout: '60%'
        }
    });
}

function createTriageChart(ctx, data) {
    return new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['True Positive', 'False Positive', 'Needs Review'],
            datasets: [{
                data: data,
                backgroundColor: ['#dc2626', '#22c55e', '#f59e0b'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#94a3b8',
                        padding: 15
                    }
                }
            }
        }
    });
}

// DOM helpers
function createElement(tag, className = '', content = '') {
    const el = document.createElement(tag);
    if (className) el.className = className;
    if (content) el.textContent = content;
    return el;
}

function showNotification(message, type = 'info') {
    const notification = createElement('div', 'notification notification-' + type, message);
    document.body.appendChild(notification);

    setTimeout(() => {
        notification.classList.add('notification-show');
    }, 10);

    setTimeout(() => {
        notification.classList.remove('notification-show');
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    // File upload handlers
    const fileInputs = document.querySelectorAll('input[type="file"][accept=".json"]');
    fileInputs.forEach(input => {
        input.addEventListener('change', async (e) => {
            const file = e.target.files[0];
            if (file) {
                // Validate file type
                if (!file.name.endsWith('.json')) {
                    showNotification('Invalid file format. Please upload a valid report.json file.', 'error');
                    return;
                }

                try {
                    const result = await uploadScanFile(file);
                    if (result.success) {
                        showNotification(result.message, 'success');
                        setTimeout(() => location.reload(), 1000);
                    } else {
                        // Handle specific error types
                        const errorMsg = result.error || 'Unknown error occurred';
                        if (errorMsg.includes('JSON') || errorMsg.includes('parse')) {
                            showNotification('Invalid file format. Please upload a valid report.json file.', 'error');
                        } else {
                            showNotification('Error: ' + errorMsg, 'error');
                        }
                    }
                } catch (error) {
                    showNotification('Upload failed: ' + error.message, 'error');
                }
            }
        });
    });

    // Clear button handler
    const clearBtn = document.querySelector('[onclick="clearScan()"]');
    if (clearBtn) {
        clearBtn.addEventListener('click', async (e) => {
            e.preventDefault();
            if (confirm('Are you sure you want to clear the current scan results?')) {
                try {
                    await clearScanResults();
                    showNotification('Scan results cleared', 'success');
                    setTimeout(() => location.reload(), 1000);
                } catch (error) {
                    showNotification('Failed to clear results', 'error');
                }
            }
        });
    }

    // Add notification styles
    const style = document.createElement('style');
    style.textContent = `
        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 1rem 1.5rem;
            border-radius: 8px;
            color: white;
            font-weight: 500;
            z-index: 1000;
            transform: translateX(400px);
            transition: transform 0.3s ease;
        }
        .notification-success { background: #22c55e; }
        .notification-error { background: #dc2626; }
        .notification-info { background: #6366f1; }
        .notification-show { transform: translateX(0); }
    `;
    document.head.appendChild(style);
});

// Export functionality
function exportToJSON() {
    fetch('/export/json')
        .then(res => res.json())
        .then(data => {
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'security-scan-' + new Date().toISOString().split('T')[0] + '.json';
            a.click();
            URL.revokeObjectURL(url);
        });
}

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Ctrl+U to upload
    if (e.ctrlKey && e.key === 'u') {
        e.preventDefault();
        document.querySelector('input[type="file"]').click();
    }
    // Escape to go home
    if (e.key === 'Escape') {
        window.location.href = '/';
    }
});

console.log('AI Security Scanner Dashboard loaded');
