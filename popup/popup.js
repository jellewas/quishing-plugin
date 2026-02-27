// DOM Elements
const scanBtn = document.getElementById('scanBtn');
const status = document.getElementById('status');
const statusText = status.querySelector('.status-text');
const result = document.getElementById('result');
const warning = document.getElementById('warning');
const decodedContent = document.getElementById('decodedContent');
const copyBtn = document.getElementById('copyBtn');
const resetBtn = document.getElementById('resetBtn');

// Extract URL from potentially messy content
function extractUrl(content) {
  if (!content) return content;
  const urlRegex = /https?:\/\/[^\s<>"']+/gi;
  const matches = content.match(urlRegex);
  if (matches && matches.length > 0) {
    return matches[0].replace(/[.,;:!?)]+$/, '');
  }
  return content;
}

// Display the result
function displayResult(content) {
  result.classList.remove('hidden');
  status.classList.add('hidden');
  scanBtn.disabled = false;
  warning.classList.add('hidden');

  // Extract URL from content
  const extracted = extractUrl(content);

  // Check if it's a URL
  let isUrl = false;
  try {
    new URL(extracted);
    isUrl = true;
  } catch (e) {}

  if (isUrl) {
    decodedContent.innerHTML = `<a href="${escapeHtml(extracted)}" target="_blank" rel="noopener noreferrer">${escapeHtml(extracted)}</a>`;
  } else {
    decodedContent.textContent = extracted;
  }
}

// Display error message
function displayError(errorMessage) {
  result.classList.add('hidden');
  status.classList.remove('hidden');
  statusText.textContent = errorMessage;
  scanBtn.disabled = false;
}

// Escape HTML
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Reset state
function resetState() {
  result.classList.add('hidden');
  status.classList.add('hidden');
  warning.classList.add('hidden');
  decodedContent.textContent = '';
  scanBtn.disabled = false;
  chrome.storage.local.remove('qrScanResult');
}

// Check for stored result
async function checkStoredResult() {
  const stored = await chrome.storage.local.get('qrScanResult');
  
  if (stored.qrScanResult) {
    const message = stored.qrScanResult;
    
    if (message.timestamp && (Date.now() - message.timestamp) < 300000) {
      if (message.action === 'scanResult') {
        if (message.success) {
          displayResult(message.data);
        } else {
          displayError(message.error || 'Failed to decode QR code');
        }
      }
    } else {
      chrome.storage.local.remove('qrScanResult');
    }
  }
}

// Scan button
scanBtn.addEventListener('click', async () => {
  scanBtn.disabled = true;
  status.classList.remove('hidden');
  result.classList.add('hidden');
  statusText.textContent = 'Opening scanner...';

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab.id) throw new Error('No active tab');

    await chrome.storage.local.remove('qrScanResult');

    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      files: ['lib/jsqr.min.js', 'content/content.js']
    });

    chrome.tabs.sendMessage(tab.id, { action: 'startScan' });
    setTimeout(() => window.close(), 300);
    
  } catch (error) {
    statusText.textContent = 'Error: ' + error.message;
    scanBtn.disabled = false;
  }
});

// Copy button
copyBtn.addEventListener('click', async () => {
  const content = decodedContent.textContent || decodedContent.innerText;
  try {
    await navigator.clipboard.writeText(content);
    copyBtn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg> Copied!`;
    setTimeout(() => {
      copyBtn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg> Copy`;
    }, 2000);
  } catch (err) {}
});

// Reset button
resetBtn.addEventListener('click', resetState);

// Initial check
checkStoredResult();
