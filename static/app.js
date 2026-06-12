// CONSTANTS & STATE
const API_URL = '';
let activeSection = 'dashboard';
let saliencyChartInstance = null;
let evaluationChartInstance = null;
let pollTimer = null;

// NAVIGATION HANDLERS
const navButtons = {
    dashboard: document.getElementById('btn-nav-dashboard'),
    profiles: document.getElementById('btn-nav-profiles'),
    logs: document.getElementById('btn-nav-logs'),
    benchmark: document.getElementById('btn-nav-benchmark')
};

const sections = {
    dashboard: document.getElementById('view-dashboard'),
    profiles: document.getElementById('view-profiles'),
    logs: document.getElementById('view-logs'),
    benchmark: document.getElementById('view-benchmark')
};

function switchSection(sectionId) {
    if (!sections[sectionId]) return;
    
    // Update active nav button
    Object.keys(navButtons).forEach(key => {
        if (key === sectionId) {
            navButtons[key].classList.add('active');
        } else {
            navButtons[key].classList.remove('active');
        }
    });

    // Update visible section
    Object.keys(sections).forEach(key => {
        if (key === sectionId) {
            sections[key].classList.remove('hidden');
        } else {
            sections[key].classList.add('hidden');
        }
    });

    activeSection = sectionId;
    
    // Instantly refresh when switching views
    refreshData();
}

// Attach nav click handlers
Object.keys(navButtons).forEach(key => {
    navButtons[key].addEventListener('click', (e) => {
        e.preventDefault();
        switchSection(key);
    });
});

// CORE DATA POLLING (1.5 seconds)
async function refreshData() {
    try {
        // 1. Fetch system status & profiles
        const statusRes = await fetch(`${API_URL}/api/status`);
        if (statusRes.ok) {
            const status = await statusRes.json();
            updateStatsCards(status);
            if (activeSection === 'profiles') {
                updateProfilesTable(status.users);
            }
        }

        // 2. Fetch queries (if on dashboard or logs section)
        if (activeSection === 'dashboard' || activeSection === 'logs') {
            const queriesRes = await fetch(`${API_URL}/api/queries`);
            if (queriesRes.ok) {
                const queries = await queriesRes.json();
                updateLogsTable(queries);
            }
        }

        // 3. Fetch alerts (if on dashboard)
        if (activeSection === 'dashboard') {
            const alertsRes = await fetch(`${API_URL}/api/alerts`);
            if (alertsRes.ok) {
                const alerts = await alertsRes.json();
                updateAlertsTable(alerts);
            }
        }
    } catch (err) {
        console.error('Error polling database status:', err);
    }
}

function startPolling() {
    refreshData();
    pollTimer = setInterval(refreshData, 1500);
}

// UPDATE STATS CARDS
function updateStatsCards(status) {
    document.getElementById('stat-total-queries').innerText = status.total_queries;
    document.getElementById('stat-total-users').innerText = status.users_count;
    document.getElementById('stat-total-alerts').innerText = status.total_alerts;
    document.getElementById('stat-reviewed-alerts').innerText = status.reviewed_alerts;
    document.getElementById('val-drift-threshold').innerText = status.drift_threshold.toFixed(2);
    
    // Add pulsing warning if alerts are high
    const alertSpan = document.getElementById('stat-total-alerts');
    if (status.open_alerts > 0) {
        alertSpan.classList.add('threat-glow');
        alertSpan.style.color = 'var(--color-critical)';
    } else {
        alertSpan.classList.remove('threat-glow');
        alertSpan.style.color = '#fff';
    }
}

// UPDATE LOGS TABLE
function updateLogsTable(queries) {
    const tableBody = document.querySelector('#table-logs tbody') || document.querySelector('#table-logs');
    if (!tableBody) return;
    
    tableBody.innerHTML = '';
    
    if (queries.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--color-text-muted);">No queries captured in log feed.</td></tr>`;
        return;
    }
    
    queries.forEach(q => {
        const tr = document.createElement('tr');
        
        // Clean failed status
        const statusBadge = q.is_failed === 1
            ? `<span class="badge status-tp" title="${q.error_message || 'Access Denied'}"><i class="fa-solid fa-circle-xmark"></i> Fail</span>`
            : `<span class="badge status-fp" style="color: var(--color-success); border-color: rgba(48,209,88,0.25);"><i class="fa-solid fa-circle-check"></i> OK</span>`;
            
        // Truncate SQL query
        const sqlText = q.query_text.length > 50 
            ? `${q.query_text.substring(0, 50)}...` 
            : q.query_text;
            
        tr.innerHTML = `
            <td style="font-family: monospace; font-size: 12px; color: var(--color-text-muted);">${q.timestamp}</td>
            <td style="font-weight: 600;">${q.username}</td>
            <td><code style="background-color: var(--color-bg-panel-alt); padding: 2px 6px; border-radius: 4px; font-size: 11px;">${q.query_type}</code></td>
            <td style="font-family: monospace; font-size: 12px; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${q.query_text}">${sqlText}</td>
            <td><span style="color: var(--color-accent); font-weight: 500;">${q.tables_accessed || '-'}</span></td>
            <td>${q.bytes_returned}</td>
            <td>${q.execution_time_ms} ms</td>
            <td>${statusBadge}</td>
        `;
        tableBody.appendChild(tr);
    });
}

// UPDATE ALERTS FEED
function updateAlertsTable(alerts) {
    const tableBody = document.querySelector('#table-alerts tbody');
    if (!tableBody) return;
    
    tableBody.innerHTML = '';
    
    if (alerts.length === 0) {
        tableBody.innerHTML = `
            <tr class="placeholder-row">
                <td colspan="7" style="text-align: center; color: var(--color-text-muted);">No security alerts detected. Run a simulation trigger.</td>
            </tr>`;
        return;
    }
    
    alerts.forEach(a => {
        const tr = document.createElement('tr');
        
        // Setup status tag
        let statusTag = '';
        if (a.status === 'OPEN') {
            statusTag = `<span class="badge status-open"><i class="fa-solid fa-envelope-open-text"></i> Open</span>`;
        } else if (a.status === 'FALSE_POSITIVE') {
            statusTag = `<span class="badge status-fp"><i class="fa-solid fa-check"></i> False Pos</span>`;
        } else {
            statusTag = `<span class="badge status-tp"><i class="fa-solid fa-ban"></i> Confirmed</span>`;
        }
        
        const riskLvl = a.alert_level.toLowerCase();
        
        tr.innerHTML = `
            <td><span class="badge ${riskLvl}">${a.alert_level}</span></td>
            <td style="font-weight: 600; color: #fff;">${a.username}</td>
            <td style="font-family: monospace; font-weight: bold; color: ${riskLvl === 'critical' ? 'var(--color-critical)' : 'inherit'};">${a.threat_score.toFixed(4)}</td>
            <td style="font-family: monospace;">${a.confidence_score.toFixed(4)}</td>
            <td>${statusTag}</td>
            <td style="color: var(--color-text-muted); font-size: 12px;">${a.timestamp}</td>
            <td><button class="btn-inspect" data-alert='${JSON.stringify(a)}'><i class="fa-solid fa-magnifying-glass"></i> Inspect</button></td>
        `;
        tableBody.appendChild(tr);
    });
    
    // Attach modal trigger listeners
    document.querySelectorAll('.btn-inspect').forEach(btn => {
        btn.addEventListener('click', () => {
            const alertData = JSON.parse(btn.getAttribute('data-alert'));
            openAlertInspectModal(alertData);
        });
    });
}

// UPDATE PROFILES TABLE
function updateProfilesTable(users) {
    const tableBody = document.querySelector('#table-profiles tbody');
    if (!tableBody) return;
    
    tableBody.innerHTML = '';
    
    users.forEach(u => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td style="font-weight: 600; color: #fff;">${u.username}</td>
            <td><code style="background-color: var(--color-bg-panel-alt); padding: 4px 8px; border-radius: 4px;">${u.role}</code></td>
            <td style="font-family: monospace;">${u.avg_queries}</td>
            <td style="font-family: monospace;">${u.avg_sensitive_access}</td>
            <td style="font-family: monospace;">${u.avg_privileged_ops}</td>
            <td style="font-family: monospace; color: ${u.off_hours_ratio > 30 ? 'var(--color-high)' : 'inherit'};">${u.off_hours_ratio}%</td>
        `;
        tableBody.appendChild(tr);
    });
}

// ATTACK TRIGGER LOGIC
document.querySelectorAll('.btn-trigger').forEach(btn => {
    btn.addEventListener('click', async () => {
        const scenario = btn.getAttribute('data-scenario');
        
        // Show loading state
        const originalContent = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> <span>Triggering...</span>`;
        btn.style.borderColor = 'var(--color-high)';
        
        try {
            const res = await fetch(`${API_URL}/api/trigger`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ scenario })
            });
            
            if (res.ok) {
                btn.style.borderColor = 'var(--color-success)';
                btn.innerHTML = `<i class="fa-solid fa-circle-check" style="color: var(--color-success);"></i> <span>Logged!</span>`;
            } else {
                btn.style.borderColor = 'var(--color-critical)';
                btn.innerHTML = `<i class="fa-solid fa-circle-exclamation" style="color: var(--color-critical);"></i> <span>Failed</span>`;
            }
        } catch (err) {
            btn.style.borderColor = 'var(--color-critical)';
            btn.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> <span>Failed</span>`;
        }
        
        // Reset button state
        setTimeout(() => {
            btn.disabled = false;
            btn.innerHTML = originalContent;
            btn.style.borderColor = 'var(--color-border)';
        }, 1500);
    });
});

// EXPLAINABILITY PARSER
function parseSaliencyExplanation(explanationText) {
    const lines = explanationText.split('\n');
    const features = [];
    const importances = [];
    
    lines.forEach(line => {
        // Parse: "- log_bytes_returned: Value = 6291456 bytes (+8.9 Std Devs from baseline) [Contrib: 48.8%]"
        if (line.trim().startsWith('- ')) {
            const match = line.match(/-\s+([a-zA-Z_]+):\s+Value\s+=\s+.+?\s+\(([-+0-9.]+)\s+Std\s+Devs.+?\)\s+\[Contrib:\s+([0-9.]+)\%\]/);
            if (match) {
                const featName = match[1].replace(/_/g, ' ');
                features.push(featName);
                importances.push(parseFloat(match[3]));
            } else {
                // Try simpler match without contribution percentages if fallback
                const fallbackMatch = line.match(/-\s+([a-zA-Z_]+):\s+Value\s+=\s+.+?\s+\(([-+0-9.]+)\s+Std\s+Devs/);
                if (fallbackMatch) {
                    features.push(fallbackMatch[1].replace(/_/g, ' '));
                    importances.push(Math.abs(parseFloat(fallbackMatch[2]))); // absolute z score deviation
                }
            }
        }
    });
    
    return { features, importances };
}

// INSPECT MODAL OPEN
function openAlertInspectModal(alert) {
    const modal = document.getElementById('modal-alert-inspect');
    
    // Set text values
    document.getElementById('modal-alert-user').innerText = alert.username;
    document.getElementById('modal-alert-threat').innerText = alert.threat_score.toFixed(4);
    document.getElementById('modal-alert-confidence').innerText = alert.confidence_score.toFixed(4);
    document.getElementById('modal-alert-uncertainty').innerText = alert.uncertainty_score.toFixed(4);
    document.getElementById('modal-alert-desc').innerText = alert.description;
    
    // Set badge style
    const riskBadge = document.getElementById('modal-alert-risk');
    riskBadge.innerText = alert.alert_level;
    riskBadge.className = `badge ${alert.alert_level.toLowerCase()}`;
    
    // Set hidden form alert id
    document.getElementById('feedback-alert-id').value = alert.id;
    
    // Clear feedback form comments
    document.getElementById('feedback-type').value = '';
    document.getElementById('feedback-comments').value = '';
    
    // Render remediation recommendations
    const actionsContainer = document.getElementById('modal-alert-actions');
    actionsContainer.innerHTML = '';
    
    const steps = alert.recommended_action.split('\n');
    steps.forEach(step => {
        if (step.trim()) {
            const p = document.createElement('p');
            // Remove listing bullet "-"
            p.innerText = step.trim().replace(/^-\s+/, '');
            actionsContainer.appendChild(p);
        }
    });

    // Destroy existing chart
    if (saliencyChartInstance) {
        saliencyChartInstance.destroy();
    }
    
    // Parse explainability metrics and plot chart
    const explanation = parseSaliencyExplanation(alert.explanation);
    const ctx = document.getElementById('chart-alert-saliency').getContext('2d');
    
    saliencyChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: explanation.features,
            datasets: [{
                label: 'Feature Gradient Saliency (%)',
                data: explanation.importances,
                backgroundColor: alert.alert_level === 'CRITICAL' ? 'rgba(255, 59, 48, 0.6)' : 'rgba(0, 240, 255, 0.6)',
                borderColor: alert.alert_level === 'CRITICAL' ? 'var(--color-critical)' : 'var(--color-accent)',
                borderWidth: 1,
                borderRadius: 4
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    beginAtZero: true,
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: 'var(--color-text-muted)' }
                },
                y: {
                    grid: { display: false },
                    ticks: { color: '#fff', font: { family: 'Outfit', size: 11 } }
                }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });

    modal.classList.remove('hidden');
}

// CLOSE MODAL HANDLERS
document.querySelectorAll('.btn-close-modal').forEach(btn => {
    btn.addEventListener('click', () => {
        document.getElementById('modal-alert-inspect').classList.add('hidden');
    });
});

// CLOSE MODAL ON OUTSIDE CLICK
window.addEventListener('click', (e) => {
    const inspectModal = document.getElementById('modal-alert-inspect');
    if (e.target === inspectModal) {
        inspectModal.classList.add('hidden');
    }
});

// REVIEW FEEDBACK FORM SUBMISSION (Adaptive Learning)
document.getElementById('form-alert-feedback').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const alertId = document.getElementById('feedback-alert-id').value;
    const feedbackType = document.getElementById('feedback-type').value;
    const comments = document.getElementById('feedback-comments').value;
    
    const submitBtn = e.target.querySelector('button[type="submit"]');
    const originalText = submitBtn.innerHTML;
    submitBtn.disabled = true;
    submitBtn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Retraining Model...`;
    
    try {
        const res = await fetch(`${API_URL}/api/feedback`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                alert_id: parseInt(alertId),
                type: feedbackType,
                comments: comments
            })
        });
        
        if (res.ok) {
            alert('Feedback recorded. Model is retraining in the background.');
            document.getElementById('modal-alert-inspect').classList.add('hidden');
            refreshData(); // Refresh UI
        } else {
            alert('Failed to submit feedback.');
        }
    } catch (err) {
        console.error('Error submitting feedback:', err);
        alert('Network error submitting feedback.');
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalText;
    }
});

// BENCHMARK RUN EVALUATION
document.getElementById('btn-run-evaluation').addEventListener('click', async () => {
    const tableBody = document.querySelector('#table-evaluation tbody');
    const loader = document.querySelector('.evaluation-loader');
    const placeholder = document.querySelector('.chart-img-placeholder');
    const canvas = document.getElementById('chart-evaluation-roc');
    
    loader.classList.remove('hidden');
    tableBody.innerHTML = '';
    
    try {
        const res = await fetch(`${API_URL}/api/evaluate`);
        if (res.ok) {
            const report = await res.json();
            
            // Populate metrics comparison table
            Object.keys(report).forEach(modelName => {
                const tr = document.createElement('tr');
                const m = report[modelName];
                
                // Highlight Deep Evidential
                const isEDL = modelName === 'Deep Evidential Model';
                const style = isEDL ? 'style="background-color: var(--color-accent-dim); font-weight: bold;"' : '';
                
                tr.innerHTML = `
                    <td ${style}>${modelName}</td>
                    <td ${style}>${m.Accuracy.toFixed(3)}</td>
                    <td ${style}>${m.Precision.toFixed(3)}</td>
                    <td ${style}>${m.Recall.toFixed(3)}</td>
                    <td ${style}>${m.F1.toFixed(3)}</td>
                    <td ${style} style="color: ${m.FPR > 0.1 && !isEDL ? 'var(--color-high)' : 'inherit'}">${m.FPR.toFixed(3)}</td>
                    <td ${style}>${m.FNR.toFixed(3)}</td>
                    <td ${style} style="color: var(--color-success); font-family: monospace;">${m.Latency.toFixed(3)} ms</td>
                `;
                tableBody.appendChild(tr);
            });
            
            // Draw chart
            placeholder.classList.add('hidden');
            canvas.classList.remove('hidden');
            
            if (evaluationChartInstance) {
                evaluationChartInstance.destroy();
            }
            
            const models = Object.keys(report);
            const accuracies = models.map(m => report[m].Accuracy);
            const f1s = models.map(m => report[m].F1);
            
            const ctx = canvas.getContext('2d');
            evaluationChartInstance = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: models.map(m => m.split(' ')[0]), # Short name
                    datasets: [
                        {
                            label: 'Accuracy',
                            data: accuracies,
                            backgroundColor: 'rgba(0, 240, 255, 0.6)',
                            borderColor: 'var(--color-accent)',
                            borderWidth: 1
                        },
                        {
                            label: 'F1-Score',
                            data: f1s,
                            backgroundColor: 'rgba(255, 159, 10, 0.6)',
                            borderColor: 'var(--color-high)',
                            borderWidth: 1
                        }
                    ]
                },
                options: {
                    responsive: true,
                    scales: {
                        x: { ticks: { color: '#fff' }, grid: { display: false } },
                        y: { min: 0, max: 1.1, ticks: { color: 'var(--color-text-muted)' }, grid: { color: 'rgba(255, 255, 255, 0.05)' } }
                    },
                    plugins: {
                        legend: { labels: { color: '#fff', font: { family: 'Outfit' } } }
                    }
                }
            });
            
        } else {
            tableBody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--color-critical);">Failed to compile benchmarks report.</td></tr>`;
        }
    } catch (err) {
        console.error('Error running evaluation:', err);
        tableBody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--color-critical);">Network error running benchmarks.</td></tr>`;
    } finally {
        loader.classList.add('hidden');
    }
});

// START
startPolling();
switchSection('dashboard'); // Start on dashboard view
