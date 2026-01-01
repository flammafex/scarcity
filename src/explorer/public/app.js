// Nullscape Explorer - Frontend Application

const API_BASE = '/api';
const WS_URL = `ws://${window.location.host}`;

let ws = null;
let currentPage = 1;
const pageSize = 50;

// Utility functions
const $ = (id) => document.getElementById(id);
const $$ = (selector) => document.querySelectorAll(selector);

function showLoading(text = 'Processing...') {
  $('loading').style.display = 'flex';
  $('loading-text').textContent = text;
}

function hideLoading() {
  $('loading').style.display = 'none';
}

function showError(message) {
  const toast = $('error-toast');
  toast.textContent = message;
  toast.style.display = 'block';
  setTimeout(() => toast.style.display = 'none', 5000);
}

function showSuccess(message) {
  const toast = $('success-toast');
  toast.textContent = message;
  toast.style.display = 'block';
  setTimeout(() => toast.style.display = 'none', 3000);
}

async function apiCall(endpoint, method = 'GET', body = null) {
  try {
    const options = {
      method,
      headers: { 'Content-Type': 'application/json' }
    };
    if (body) {
      options.body = JSON.stringify(body);
    }

    const response = await fetch(`${API_BASE}${endpoint}`, options);
    const data = await response.json();

    if (!data.success) {
      throw new Error(data.error || 'Request failed');
    }

    return data.data;
  } catch (error) {
    console.error('API Error:', error);
    throw error;
  }
}

// Tab navigation
function setupTabs() {
  $$('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const tab = btn.dataset.tab;

      // Update buttons
      $$('.tab-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      // Update content
      $$('.tab-content').forEach(c => c.classList.remove('active'));
      $(`${tab}-tab`).classList.add('active');

      // Load tab-specific data
      if (tab === 'activity') loadActivity();
      if (tab === 'federations') loadFederations();
    });
  });
}

// WebSocket connection
function connectWebSocket() {
  if (ws && ws.readyState === WebSocket.OPEN) {
    return;
  }

  ws = new WebSocket(WS_URL);

  ws.onopen = () => {
    console.log('WebSocket connected');
    $('live-indicator').classList.add('active');
    $('live-text').textContent = 'Live';
  };

  ws.onclose = () => {
    console.log('WebSocket disconnected');
    $('live-indicator').classList.remove('active');
    $('live-text').textContent = 'Offline';

    // Reconnect after 5 seconds
    setTimeout(connectWebSocket, 5000);
  };

  ws.onerror = (error) => {
    console.error('WebSocket error:', error);
  };

  ws.onmessage = (event) => {
    const message = JSON.parse(event.data);

    if (message.type === 'nullifier') {
      handleNewNullifier(message.data);
      updateStats();
    } else if (message.type === 'stats') {
      displayStats(message.data);
    }
  };
}

// Handle new nullifier from WebSocket
function handleNewNullifier(data) {
  const feed = $('nullifier-feed');
  const emptyState = feed.querySelector('.empty-state');
  if (emptyState) {
    emptyState.remove();
  }

  const item = createNullifierItem({
    nullifierHex: data.nullifierHex,
    timestamp: data.timestamp,
    proof: data.proof,
    peerCount: 1,
    witnessDepth: data.proof?.signatures?.length || 0,
    firstSeen: data.timestamp
  });

  item.classList.add('new');
  feed.insertBefore(item, feed.firstChild);

  // Remove animation class after it completes
  setTimeout(() => item.classList.remove('new'), 500);

  // Limit feed to 100 items
  const items = feed.querySelectorAll('.nullifier-item');
  if (items.length > 100) {
    items[items.length - 1].remove();
  }
}

// Start collector
async function startCollector() {
  try {
    const federation = $('federation-input').value.trim() || undefined;

    showLoading('Starting collector...');
    await apiCall('/start', 'POST', { federation });

    $('status-indicator').classList.add('online');
    $('status-text').textContent = 'Collecting';
    $('start-btn').disabled = true;
    $('stop-btn').disabled = false;

    connectWebSocket();
    loadNullifiers();
    updateStats();

    showSuccess('Collector started');
  } catch (error) {
    showError('Failed to start: ' + error.message);
  } finally {
    hideLoading();
  }
}

// Stop collector
async function stopCollector() {
  try {
    showLoading('Stopping collector...');
    await apiCall('/stop', 'POST');

    $('status-indicator').classList.remove('online');
    $('status-text').textContent = 'Stopped';
    $('start-btn').disabled = false;
    $('stop-btn').disabled = true;

    if (ws) {
      ws.close();
    }

    showSuccess('Collector stopped');
  } catch (error) {
    showError('Failed to stop: ' + error.message);
  } finally {
    hideLoading();
  }
}

// Update stats
async function updateStats() {
  try {
    const data = await apiCall('/stats');
    displayStats(data.network);
  } catch (error) {
    console.error('Failed to update stats:', error);
  }
}

// Display stats
function displayStats(stats) {
  $('stat-total').textContent = stats.totalNullifiers.toLocaleString();
  $('stat-24h').textContent = stats.last24h.toLocaleString();
  $('stat-hour').textContent = stats.lastHour.toLocaleString();
  $('stat-federations').textContent = stats.activeFederations.toLocaleString();
  $('stat-peers').textContent = stats.avgPeerCount.toLocaleString();
  $('stat-depth').textContent = stats.avgWitnessDepth.toLocaleString();
}

// Load nullifiers
async function loadNullifiers() {
  try {
    const offset = (currentPage - 1) * pageSize;
    const data = await apiCall(`/nullifiers?limit=${pageSize}&offset=${offset}`);

    const feed = $('nullifier-feed');
    feed.innerHTML = '';

    if (data.nullifiers.length === 0) {
      feed.innerHTML = '<div class="empty-state"><p>No nullifiers found.</p></div>';
      return;
    }

    data.nullifiers.forEach(nullifier => {
      feed.appendChild(createNullifierItem(nullifier));
    });

    // Update pagination
    $('page-info').textContent = `Page ${currentPage}`;
    $('prev-btn').disabled = currentPage === 1;
    $('next-btn').disabled = data.nullifiers.length < pageSize;
  } catch (error) {
    showError('Failed to load nullifiers: ' + error.message);
  }
}

// Create nullifier item element
function createNullifierItem(nullifier) {
  const item = document.createElement('div');
  item.className = 'nullifier-item';

  const timeAgo = getTimeAgo(nullifier.firstSeen);
  const shortHex = nullifier.nullifierHex.substring(0, 32) + '...';

  item.innerHTML = `
    <div class="nullifier-header">
      <div class="nullifier-hex">${shortHex}</div>
      <span class="nullifier-badge">${nullifier.peerCount} peers</span>
    </div>
    <div class="nullifier-meta">
      <span>⏱️ ${timeAgo}</span>
      <span>🔐 Depth: ${nullifier.witnessDepth}</span>
      ${nullifier.federation ? `<span>🏛️ ${nullifier.federation}</span>` : ''}
    </div>
  `;

  item.addEventListener('click', () => showNullifierDetails(nullifier));

  return item;
}

// Show nullifier details in modal
function showNullifierDetails(nullifier) {
  const modal = $('modal');
  const body = $('modal-body');

  body.innerHTML = `
    <div class="detail-row">
      <div class="detail-label">Nullifier (Hex)</div>
      <div class="detail-value">${nullifier.nullifierHex}</div>
    </div>
    <div class="detail-row">
      <div class="detail-label">Token ID</div>
      <div class="detail-value">${nullifier.tokenId || 'N/A'}</div>
    </div>
    <div class="detail-row">
      <div class="detail-label">Timestamp</div>
      <div class="detail-value">${new Date(nullifier.timestamp).toLocaleString()}</div>
    </div>
    <div class="detail-row">
      <div class="detail-label">First Seen</div>
      <div class="detail-value">${new Date(nullifier.firstSeen).toLocaleString()}</div>
    </div>
    <div class="detail-row">
      <div class="detail-label">Peer Count</div>
      <div class="detail-value">${nullifier.peerCount}</div>
    </div>
    <div class="detail-row">
      <div class="detail-label">Witness Depth</div>
      <div class="detail-value">${nullifier.witnessDepth}</div>
    </div>
    <div class="detail-row">
      <div class="detail-label">Federation</div>
      <div class="detail-value">${nullifier.federation || 'N/A'}</div>
    </div>
    <div class="detail-row">
      <div class="detail-label">Proof</div>
      <div class="detail-value"><pre>${JSON.stringify(nullifier.proof, null, 2)}</pre></div>
    </div>
  `;

  modal.style.display = 'block';
}

// Search nullifiers
async function searchNullifiers() {
  const query = $('search-input').value.trim();
  if (!query) {
    showError('Please enter a search query');
    return;
  }

  try {
    showLoading('Searching...');
    const data = await apiCall(`/nullifiers/search?q=${encodeURIComponent(query)}`);

    const feed = $('nullifier-feed');
    feed.innerHTML = '';

    if (data.nullifiers.length === 0) {
      feed.innerHTML = '<div class="empty-state"><p>No nullifiers found matching your search.</p></div>';
      return;
    }

    data.nullifiers.forEach(nullifier => {
      feed.appendChild(createNullifierItem(nullifier));
    });

    showSuccess(`Found ${data.nullifiers.length} nullifiers`);
  } catch (error) {
    showError('Search failed: ' + error.message);
  } finally {
    hideLoading();
  }
}

// Load activity chart
async function loadActivity() {
  try {
    const data = await apiCall('/activity/hourly');
    drawActivityChart(data.activity);
  } catch (error) {
    showError('Failed to load activity: ' + error.message);
  }
}

// Draw activity chart
function drawActivityChart(activity) {
  const canvas = $('activity-chart');
  const ctx = canvas.getContext('2d');
  const width = canvas.width;
  const height = canvas.height;

  // Clear canvas
  ctx.clearRect(0, 0, width, height);

  if (activity.length === 0) {
    ctx.fillStyle = '#94a3b8';
    ctx.font = '16px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('No activity data available', width / 2, height / 2);
    return;
  }

  // Find max count for scaling
  const maxCount = Math.max(...activity.map(a => a.count), 1);

  // Draw bars
  const barWidth = width / activity.length;
  const padding = 40;
  const chartHeight = height - padding * 2;

  activity.forEach((item, i) => {
    const barHeight = (item.count / maxCount) * chartHeight;
    const x = i * barWidth;
    const y = height - padding - barHeight;

    // Draw bar
    ctx.fillStyle = '#3b82f6';
    ctx.fillRect(x + 2, y, barWidth - 4, barHeight);

    // Draw count
    if (item.count > 0) {
      ctx.fillStyle = '#f1f5f9';
      ctx.font = '10px sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(item.count, x + barWidth / 2, y - 5);
    }
  });

  // Draw labels
  ctx.fillStyle = '#94a3b8';
  ctx.font = '10px sans-serif';
  ctx.textAlign = 'center';
  activity.forEach((item, i) => {
    if (i % 3 === 0) { // Show every 3rd label
      const x = i * barWidth + barWidth / 2;
      const hour = item.hour.split(' ')[1];
      ctx.fillText(hour, x, height - 10);
    }
  });
}

// Load federations
async function loadFederations() {
  try {
    const data = await apiCall('/federations/stats');

    const list = $('federation-stats');
    list.innerHTML = '';

    if (data.federations.length === 0) {
      list.innerHTML = '<div class="empty-state"><p>No federation data available.</p></div>';
      return;
    }

    data.federations.forEach(fed => {
      const item = document.createElement('div');
      item.className = 'federation-item';
      item.innerHTML = `
        <div class="federation-name">${fed.federation}</div>
        <div class="federation-stats">
          <span>${fed.count.toLocaleString()} nullifiers</span>
          <span>${Math.round(fed.avgPeerCount)} avg peers</span>
        </div>
      `;
      list.appendChild(item);
    });
  } catch (error) {
    showError('Failed to load federations: ' + error.message);
  }
}

// Helper: Get time ago string
function getTimeAgo(timestamp) {
  const seconds = Math.floor((Date.now() - timestamp) / 1000);

  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
  setupTabs();

  // Control buttons
  $('start-btn').addEventListener('click', startCollector);
  $('stop-btn').addEventListener('click', stopCollector);

  // Search
  $('search-btn').addEventListener('click', searchNullifiers);
  $('search-input').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') searchNullifiers();
  });

  // Pagination
  $('prev-btn').addEventListener('click', () => {
    currentPage--;
    loadNullifiers();
  });

  $('next-btn').addEventListener('click', () => {
    currentPage++;
    loadNullifiers();
  });

  // Modal close
  $('modal').querySelector('.close').addEventListener('click', () => {
    $('modal').style.display = 'none';
  });

  window.addEventListener('click', (e) => {
    if (e.target === $('modal')) {
      $('modal').style.display = 'none';
    }
  });

  // Initial stats load
  updateStats();

  // Auto-refresh stats every 10 seconds
  setInterval(updateStats, 10000);

  // Auto-refresh nullifiers every 5 seconds (when on feed tab)
  setInterval(() => {
    // Only refresh if we're on the feed tab
    if ($('feed-tab').classList.contains('active')) {
      loadNullifiers();
    }
  }, 5000);
});
