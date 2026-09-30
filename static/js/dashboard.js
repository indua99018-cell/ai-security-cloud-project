const MAX_POINTS = 30;

const cpuCtx = document.getElementById('cpuChart').getContext('2d');
const anomalyCtx = document.getElementById('anomalyChart').getContext('2d');

const chartDefaults = {
  responsive: true,
  animation: { duration: 300 },
  interaction: { mode: 'index', intersect: false },
  scales: {
    x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#8593AC', font: { size: 10 } } },
    y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#8593AC', font: { size: 10 } }, beginAtZero: true }
  },
  plugins: { legend: { labels: { color: '#E7ECF5', font: { size: 11 } } } }
};

const cpuChart = new Chart(cpuCtx, {
  type: 'line',
  data: {
    labels: [],
    datasets: [
      { label: 'Actual CPU %', data: [], borderColor: '#5B8DEF', backgroundColor: 'rgba(91,141,239,0.08)', tension: 0.35, pointRadius: 0, borderWidth: 2, fill: true },
      { label: 'AI Predicted CPU %', data: [], borderColor: '#F0B429', borderDash: [5, 4], tension: 0.35, pointRadius: 0, borderWidth: 2 }
    ]
  },
  options: { ...chartDefaults, scales: { ...chartDefaults.scales, y: { ...chartDefaults.scales.y, max: 100 } } }
});

const anomalyChart = new Chart(anomalyCtx, {
  type: 'line',
  data: {
    labels: [],
    datasets: [
      { label: 'Anomaly Score', data: [], borderColor: '#EF4444', backgroundColor: 'rgba(239,68,68,0.10)', tension: 0.35, pointRadius: 0, borderWidth: 2, fill: true },
      { label: 'Security Score', data: [], borderColor: '#34D399', tension: 0.35, pointRadius: 0, borderWidth: 2 }
    ]
  },
  options: { ...chartDefaults, scales: { ...chartDefaults.scales, y: { ...chartDefaults.scales.y, max: 100 } } }
});

function timeAgoLabel(t) { return t; }

function updateStats(latest, instances, blocked) {
  document.getElementById('statInstances').textContent = instances;
  document.getElementById('statCpu').textContent = latest.features.cpu_usage.toFixed(0) + '%';
  document.getElementById('statSecurity').textContent = latest.threat.security_score.toFixed(0);
  document.getElementById('statThreat').textContent = latest.threat.severity;
  document.getElementById('statBlocked').textContent = blocked;

  const card = document.getElementById('threatCard');
  card.className = '';
  card.classList.add('level-' + latest.threat.severity);
}

function renderCharts(history) {
  const slice = history.slice(-MAX_POINTS);
  const labels = slice.map(h => h.time);

  cpuChart.data.labels = labels;
  cpuChart.data.datasets[0].data = slice.map(h => h.features.cpu_usage);
  cpuChart.data.datasets[1].data = slice.map(h => h.prediction.predicted_cpu);
  cpuChart.update('none');

  anomalyChart.data.labels = labels;
  anomalyChart.data.datasets[0].data = slice.map(h => h.threat.anomaly_score);
  anomalyChart.data.datasets[1].data = slice.map(h => h.threat.security_score);
  anomalyChart.update('none');
}

function renderScalingList(scalingHistory) {
  const el = document.getElementById('scalingList');
  el.innerHTML = scalingHistory.map(d => `
    <div class="log-item">
      <div class="log-top">
        <span>${d.time}</span>
        <span class="badge ${d.action}">${d.action.replace('_',' ')}</span>
      </div>
      <div>${d.reason} <strong>(${d.before} → ${d.after} instances)</strong></div>
    </div>
  `).join('') || '<div class="log-item">No scaling actions yet…</div>';
}

function renderAlerts(alertList) {
  const el = document.getElementById('alertsList');
  el.innerHTML = alertList.map(a => `
    <div class="log-item level-${a.level}">
      <div class="log-top">
        <span>${a.timestamp.split(' ')[1]} · ${a.category}</span>
        <span>${a.level}</span>
      </div>
      <div>${a.message}</div>
    </div>
  `).join('') || '<div class="log-item">No alerts yet…</div>';
}

function renderTable(history) {
  const body = document.getElementById('featureTableBody');
  const rows = history.slice(-12).reverse();
  body.innerHTML = rows.map(h => `
    <tr class="${h.ground_truth === 'attack' ? 'attack-row' : ''}">
      <td>${h.tick}</td>
      <td>${h.time}</td>
      <td>${h.features.cpu_usage.toFixed(0)}</td>
      <td>${h.features.memory_usage.toFixed(0)}</td>
      <td>${h.features.request_rate.toFixed(0)}</td>
      <td>${h.features.avg_response_time.toFixed(0)}</td>
      <td>${h.features.error_rate.toFixed(1)}</td>
      <td>${h.features.unique_ips.toFixed(0)}</td>
      <td>${h.features.login_failures.toFixed(0)}</td>
      <td><span class="tag ${h.threat.is_threat ? 'attack' : 'normal'}">${h.threat.is_threat ? h.threat.severity : 'CLEAN'}</span></td>
    </tr>
  `).join('');
}

async function poll() {
  try {
    const res = await fetch('/api/state');
    const data = await res.json();
    if (data.history.length === 0) return;

    const latest = data.history[data.history.length - 1];
    updateStats(latest, data.current_instances, data.blocked_sources);
    renderCharts(data.history);
    renderScalingList(data.scaling_history);
    renderAlerts(data.alerts);
    renderTable(data.history);
  } catch (e) {
    console.error('poll failed', e);
  }
}

document.getElementById('resetBtn').addEventListener('click', async () => {
  await fetch('/api/reset', { method: 'POST' });
  poll();
});

document.getElementById('loadTestDdosBtn').addEventListener('click', () => {
  fetch('/api/simulate_load', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ kind: 'ddos', duration: 15 })
  });
});

document.getElementById('loadTestBruteBtn').addEventListener('click', () => {
  fetch('/api/simulate_load', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ kind: 'bruteforce', duration: 15 })
  });
});

poll();
setInterval(poll, 2000);
