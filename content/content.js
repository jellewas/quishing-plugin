(function() {
  if (window.__qrScannerInjected) {
    window.__qrScannerStartScan();
    return;
  }
  window.__qrScannerInjected = true;

  // URL shorteners and suspicious TLDs for analysis
  const URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'adf.ly', 'bit.do', 'mcaf.ee', 'cutt.ly', 'rebrand.ly', 'short.io', 'tiny.cc'
  ];

  const SUSPICIOUS_TLDS = [
    '.xyz', '.top', '.click', '.link', '.work', '.date', '.download',
    '.stream', '.gdn', '.racing', '.win', '.bid', '.loan', '.trade'
  ];

  // Extract URL from content (handles messy QR data like "316254 http://... Name: url")
  function extractUrl(content) {
    if (!content) return content;
    const urlRegex = /https?:\/\/[^\s<>"']+/gi;
    const matches = content.match(urlRegex);
    if (matches && matches.length > 0) {
      return matches[0].replace(/[.,;:!?)]+$/, ''); // Clean trailing punctuation
    }
    return content;
  }

  function analyzeUrl(url) {
    const warnings = [];
    let riskLevel = 'low';

    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname.toLowerCase();
      const fullUrl = url.toLowerCase();
      const path = urlObj.pathname.toLowerCase();

      // IP address instead of domain
      if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
        warnings.push('Uses IP address instead of domain name');
        riskLevel = 'high';
      }

      // URL shorteners
      for (const shortener of URL_SHORTENERS) {
        if (hostname === shortener || hostname.endsWith('.' + shortener)) {
          warnings.push('Shortened URL - destination unknown');
          riskLevel = riskLevel === 'high' ? 'high' : 'medium';
          break;
        }
      }

      // Suspicious TLDs
      for (const tld of SUSPICIOUS_TLDS) {
        if (hostname.endsWith(tld)) {
          warnings.push('Suspicious domain extension');
          riskLevel = riskLevel === 'high' ? 'high' : 'medium';
          break;
        }
      }

      // Excessive subdomains
      if (hostname.split('.').length > 4) {
        warnings.push('Unusually many subdomains');
        riskLevel = riskLevel === 'high' ? 'high' : 'medium';
      }

      // @ symbol can hide real destination
      if (url.includes('@') && !url.startsWith('mailto:')) {
        warnings.push('Contains @ symbol (may hide real destination)');
        riskLevel = 'high';
      }

      // Dangerous protocols
      if (urlObj.protocol === 'data:' || urlObj.protocol === 'javascript:') {
        warnings.push('Potentially dangerous protocol');
        riskLevel = 'high';
      }

      // HTTP instead of HTTPS
      if (urlObj.protocol === 'http:') {
        const sensitiveKeywords = ['login', 'signin', 'password', 'account', 'bank', 'pay'];
        if (sensitiveKeywords.some(kw => fullUrl.includes(kw))) {
          warnings.push('Insecure connection (HTTP) for sensitive page');
          riskLevel = 'high';
        } else {
          warnings.push('Uses HTTP instead of HTTPS');
          riskLevel = riskLevel === 'low' ? 'medium' : riskLevel;
        }
      }

      // Homograph attacks (Cyrillic characters)
      if (/[\u0400-\u04FF]/.test(hostname)) {
        warnings.push('Contains non-Latin characters (possible homograph attack)');
        riskLevel = 'high';
      }

      // Suspicious keywords in path
      const phishingKeywords = ['verify', 'secure', 'update', 'confirm', 'suspend', 'locked'];
      for (const keyword of phishingKeywords) {
        if (path.includes(keyword)) {
          warnings.push('Contains suspicious keywords in URL path');
          riskLevel = riskLevel === 'low' ? 'medium' : riskLevel;
          break;
        }
      }

    } catch (e) {
      return { warnings: [], riskLevel: 'low', isUrl: false };
    }

    return { warnings, riskLevel, isUrl: true };
  }

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
  
  // Inject styles
  const style = document.createElement('style');
  style.id = 'qr-scanner-styles';
  style.textContent = `
    .qr-scanner-highlight {
      outline: 3px solid #3b82f6 !important;
      outline-offset: 3px !important;
      cursor: crosshair !important;
      transition: all 0.15s ease !important;
      z-index: 2147483645 !important;
      border-radius: 4px !important;
    }
    .qr-scanner-highlight:hover {
      outline-color: #10b981 !important;
      outline-width: 4px !important;
    }
    .qr-scanner-overlay {
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0, 0, 0, 0.6);
      backdrop-filter: blur(2px);
      z-index: 2147483640;
      cursor: crosshair;
    }
    .qr-scanner-panel {
      position: fixed;
      top: 24px;
      right: 24px;
      width: 320px;
      background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 16px;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
      z-index: 2147483647;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      color: #f1f5f9;
    }
    .qr-scanner-panel-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 16px 18px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.06);
    }
    .qr-scanner-panel-title {
      font-size: 15px;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 8px;
      color: #f8fafc;
    }
    .qr-scanner-panel-title svg { color: #3b82f6; }
    .qr-scanner-panel-close {
      background: rgba(255, 255, 255, 0.05);
      border: none;
      color: #94a3b8;
      cursor: pointer;
      width: 28px;
      height: 28px;
      border-radius: 6px;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: all 0.2s ease;
    }
    .qr-scanner-panel-close:hover {
      background: rgba(239, 68, 68, 0.2);
      color: #ef4444;
    }
    .qr-scanner-panel-body { padding: 16px 18px; }
    .qr-scanner-status {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 14px;
      background: rgba(59, 130, 246, 0.1);
      border: 1px solid rgba(59, 130, 246, 0.2);
      border-radius: 10px;
      color: #93c5fd;
      font-size: 13px;
      font-weight: 500;
    }
    .qr-scanner-spinner {
      width: 20px;
      height: 20px;
      border: 2px solid rgba(59, 130, 246, 0.3);
      border-top-color: #3b82f6;
      border-radius: 50%;
      animation: qr-spin 0.7s linear infinite;
    }
    @keyframes qr-spin { to { transform: rotate(360deg); } }
    .qr-scanner-result { display: none; }
    .qr-scanner-result.visible { display: block; }
    .qr-scanner-warning {
      display: flex;
      align-items: flex-start;
      gap: 10px;
      padding: 12px 14px;
      margin-bottom: 14px;
      border-radius: 10px;
      font-size: 12px;
      line-height: 1.5;
      font-weight: 500;
    }
    .qr-scanner-warning svg { flex-shrink: 0; margin-top: 1px; }
    .qr-scanner-warning.level-low {
      background: rgba(16, 185, 129, 0.1);
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.25);
    }
    .qr-scanner-warning.level-medium {
      background: rgba(245, 158, 11, 0.1);
      color: #fbbf24;
      border: 1px solid rgba(245, 158, 11, 0.25);
    }
    .qr-scanner-warning.level-high {
      background: rgba(239, 68, 68, 0.1);
      color: #f87171;
      border: 1px solid rgba(239, 68, 68, 0.25);
    }
    .qr-scanner-content-label {
      font-size: 10px;
      font-weight: 600;
      color: #64748b;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 8px;
    }
    .qr-scanner-content {
      background: rgba(0, 0, 0, 0.3);
      padding: 12px;
      border-radius: 8px;
      font-size: 13px;
      line-height: 1.5;
      word-break: break-all;
      max-height: 80px;
      overflow-y: auto;
      border: 1px solid rgba(255, 255, 255, 0.05);
    }
    .qr-scanner-content a {
      color: #60a5fa;
      text-decoration: none;
    }
    .qr-scanner-content a:hover {
      text-decoration: underline;
      color: #93c5fd;
    }
    .qr-scanner-actions {
      display: flex;
      gap: 8px;
      margin-top: 14px;
    }
    .qr-scanner-btn {
      flex: 1;
      padding: 10px 14px;
      border: none;
      border-radius: 8px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      transition: all 0.2s ease;
    }
    .qr-scanner-btn-primary {
      background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
      color: white;
      box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
    }
    .qr-scanner-btn-primary:hover {
      transform: translateY(-1px);
      box-shadow: 0 6px 16px rgba(59, 130, 246, 0.4);
    }
    .qr-scanner-btn-secondary {
      background: rgba(255, 255, 255, 0.05);
      color: #cbd5e1;
      border: 1px solid rgba(255, 255, 255, 0.1);
    }
    .qr-scanner-btn-secondary:hover {
      background: rgba(255, 255, 255, 0.1);
      color: #f1f5f9;
    }
    .qr-scanner-hint {
      font-size: 11px;
      color: #64748b;
      margin-top: 14px;
      text-align: center;
      padding-top: 14px;
      border-top: 1px solid rgba(255, 255, 255, 0.06);
    }
    .qr-scanner-hint kbd {
      background: rgba(255, 255, 255, 0.1);
      padding: 2px 6px;
      border-radius: 4px;
      font-family: inherit;
      font-weight: 500;
      color: #94a3b8;
    }
    .qr-scanner-upload { margin-top: 16px; }
    .qr-scanner-divider {
      display: flex;
      align-items: center;
      margin-bottom: 14px;
      color: #64748b;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .qr-scanner-divider::before,
    .qr-scanner-divider::after {
      content: '';
      flex: 1;
      height: 1px;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent);
    }
    .qr-scanner-divider span { padding: 0 12px; }
    .qr-scanner-upload-area {
      border: 2px dashed rgba(255, 255, 255, 0.15);
      border-radius: 12px;
      padding: 20px 16px;
      text-align: center;
      cursor: pointer;
      transition: all 0.2s ease;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 10px;
      background: rgba(255, 255, 255, 0.02);
    }
    .qr-scanner-upload-area svg,
    .qr-scanner-upload-area span { pointer-events: none; }
    .qr-scanner-file-input {
      position: absolute;
      width: 1px;
      height: 1px;
      padding: 0;
      margin: -1px;
      overflow: hidden;
      clip: rect(0, 0, 0, 0);
      border: 0;
    }
    .qr-scanner-upload-area:hover {
      border-color: #3b82f6;
      background: rgba(59, 130, 246, 0.08);
    }
    .qr-scanner-upload-area.drag-over {
      border-color: #10b981;
      background: rgba(16, 185, 129, 0.1);
      border-style: solid;
    }
    .qr-scanner-upload-area svg { color: #3b82f6; opacity: 0.9; }
    .qr-scanner-upload-text { color: #cbd5e1; font-size: 13px; font-weight: 500; }
    .qr-scanner-upload-hint { font-size: 11px; color: #64748b; }
    .qr-scanner-scan-page-btn { width: 100%; margin-bottom: 4px; }
    .qr-scanner-qr-overlay {
      position: fixed;
      border: 3px solid #10b981;
      background: rgba(16, 185, 129, 0.15);
      cursor: pointer;
      z-index: 2147483646;
      border-radius: 8px;
      animation: qr-pulse 1.5s ease-in-out infinite;
    }
    .qr-scanner-qr-overlay:hover {
      border-color: #3b82f6;
      background: rgba(59, 130, 246, 0.25);
    }
    @keyframes qr-pulse {
      0%, 100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.4); }
      50% { box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }
    }
  `;
  
  if (!document.getElementById('qr-scanner-styles')) {
    document.head.appendChild(style);
  }

  let isScanning = false;
  let overlay = null;
  let panel = null;
  let currentDecodedContent = null;
  let qrOverlays = [];

  function createPanel() {
    panel = document.createElement('div');
    panel.className = 'qr-scanner-panel';
    panel.innerHTML = `
      <div class="qr-scanner-panel-header">
        <div class="qr-scanner-panel-title">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="3" width="7" height="7"/>
            <rect x="14" y="3" width="7" height="7"/>
            <rect x="3" y="14" width="7" height="7"/>
            <rect x="14" y="14" width="3" height="3"/>
            <rect x="18" y="18" width="3" height="3"/>
          </svg>
          QR Scanner
        </div>
        <button class="qr-scanner-panel-close" id="qr-close-btn">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <line x1="18" y1="6" x2="6" y2="18"/>
            <line x1="6" y1="6" x2="18" y2="18"/>
          </svg>
        </button>
      </div>
      <div class="qr-scanner-panel-body">
        <div class="qr-scanner-status" id="qr-status">
          <div class="qr-scanner-spinner"></div>
          <span>Click on a QR code image...</span>
        </div>
        
        <div class="qr-scanner-upload" id="qr-upload">
          <div class="qr-scanner-divider"><span>or</span></div>
          <button class="qr-scanner-btn qr-scanner-btn-secondary qr-scanner-scan-page-btn" id="qr-scan-page-btn">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="2" y="3" width="20" height="14" rx="2"/>
              <line x1="8" y1="21" x2="16" y2="21"/>
              <line x1="12" y1="17" x2="12" y2="21"/>
            </svg>
            Scan Visible Page
          </button>
          <div class="qr-scanner-divider" style="margin-top: 14px;"><span>or upload</span></div>
          <label class="qr-scanner-upload-area" id="qr-upload-area" for="qr-file-input">
            <input type="file" id="qr-file-input" accept="image/*" class="qr-scanner-file-input">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
              <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
              <polyline points="17 8 12 3 7 8"/>
              <line x1="12" y1="3" x2="12" y2="15"/>
            </svg>
            <span class="qr-scanner-upload-text">Drop image or click</span>
            <span class="qr-scanner-upload-hint">or paste from clipboard</span>
          </label>
        </div>
        
        <div class="qr-scanner-result" id="qr-result">
          <div class="qr-scanner-warning" id="qr-warning" style="display: none;">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 2L1 21h22L12 2zm0 3.5L19.5 19h-15L12 5.5zM11 10v4h2v-4h-2zm0 6v2h2v-2h-2z"/>
            </svg>
            <span id="qr-warning-text"></span>
          </div>
          <div class="qr-scanner-content-label">Decoded Content</div>
          <div class="qr-scanner-content" id="qr-content"></div>
          <div class="qr-scanner-actions">
            <button class="qr-scanner-btn qr-scanner-btn-secondary" id="qr-copy-btn">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <rect x="9" y="9" width="13" height="13" rx="2"/>
                <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
              </svg>
              Copy
            </button>
            <button class="qr-scanner-btn qr-scanner-btn-primary" id="qr-analyze-btn">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"/>
                <path d="M12 16v-4"/>
                <path d="M12 8h.01"/>
              </svg>
              Analyze
            </button>
          </div>
          <div class="qr-scanner-actions" style="margin-top: 6px;">
            <button class="qr-scanner-btn qr-scanner-btn-secondary" id="qr-scan-again-btn" style="flex: 1;">Scan Again</button>
          </div>
        </div>
        <div class="qr-scanner-hint" id="qr-hint">Press <kbd>ESC</kbd> to cancel</div>
      </div>
    `;
    document.body.appendChild(panel);

    // Event listeners
    panel.querySelector('#qr-close-btn')?.addEventListener('click', cancelScanning);
    panel.querySelector('#qr-copy-btn')?.addEventListener('click', copyContent);
    panel.querySelector('#qr-scan-again-btn')?.addEventListener('click', () => {
      showScanningState();
      activateImageSelection();
    });
    panel.querySelector('#qr-analyze-btn')?.addEventListener('click', analyzeCurrentUrl);
    panel.querySelector('#qr-scan-page-btn')?.addEventListener('click', scanVisiblePage);

    // File upload
    const fileInput = panel.querySelector('#qr-file-input');
    const uploadArea = panel.querySelector('#qr-upload-area');

    fileInput?.addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (file) processImageFile(file);
      e.target.value = '';
    });

    uploadArea?.addEventListener('dragover', (e) => {
      e.preventDefault();
      uploadArea.classList.add('drag-over');
    });
    uploadArea?.addEventListener('dragleave', (e) => {
      e.preventDefault();
      uploadArea.classList.remove('drag-over');
    });
    uploadArea?.addEventListener('drop', (e) => {
      e.preventDefault();
      uploadArea.classList.remove('drag-over');
      const file = e.dataTransfer.files[0];
      if (file?.type.startsWith('image/')) processImageFile(file);
    });

    document.addEventListener('paste', handlePaste);
  }

  async function copyContent() {
    const contentEl = panel?.querySelector('#qr-content');
    if (!contentEl) return;
    try {
      await navigator.clipboard.writeText(contentEl.textContent);
      const btn = panel.querySelector('#qr-copy-btn');
      if (btn) {
        btn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg> Copied!`;
        setTimeout(() => {
          btn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg> Copy`;
        }, 2000);
      }
    } catch (err) {}
  }

  function handlePaste(e) {
    if (!panel) return;
    const items = e.clipboardData?.items;
    if (!items) return;
    for (const item of items) {
      if (item.type.startsWith('image/')) {
        e.preventDefault();
        const file = item.getAsFile();
        if (file) processImageFile(file);
        break;
      }
    }
  }

  async function processImageFile(file) {
    if (!panel) return;
    const uploadDiv = panel.querySelector('#qr-upload');
    const statusEl = panel.querySelector('#qr-status');
    const statusSpan = statusEl?.querySelector('span');
    
    if (uploadDiv) uploadDiv.style.display = 'none';
    if (statusEl) statusEl.style.display = 'flex';
    if (statusSpan) statusSpan.textContent = 'Processing image...';

    if (overlay) { overlay.remove(); overlay = null; }
    deactivateImageSelection();

    try {
      if (typeof jsQR === 'undefined') {
        showResult('QR decoder not loaded', true);
        return;
      }

      const imageData = await loadFileToImageData(file);
      if (!imageData) {
        showResult('Could not process image', true);
        return;
      }

      const code = jsQR(imageData.data, imageData.width, imageData.height);
      if (code) {
        showResult(code.data);
      } else {
        showResult('No QR code found in image', true);
      }
    } catch (error) {
      showResult(error.message || 'Failed to process image', true);
    }

    isScanning = false;
    document.removeEventListener('keydown', handleEscape);
  }

  function loadFileToImageData(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        const img = new Image();
        img.onload = () => {
          const canvas = document.createElement('canvas');
          const ctx = canvas.getContext('2d');
          canvas.width = img.width;
          canvas.height = img.height;
          ctx.drawImage(img, 0, 0);
          try {
            resolve(ctx.getImageData(0, 0, canvas.width, canvas.height));
          } catch (err) {
            reject(new Error('Failed to process image'));
          }
        };
        img.onerror = () => reject(new Error('Failed to load image'));
        img.src = e.target.result;
      };
      reader.onerror = () => reject(new Error('Failed to read file'));
      reader.readAsDataURL(file);
    });
  }

  function showScanningState() {
    if (!panel) return;
    const statusEl = panel.querySelector('#qr-status');
    const resultEl = panel.querySelector('#qr-result');
    const hintEl = panel.querySelector('#qr-hint');
    const uploadEl = panel.querySelector('#qr-upload');
    const warningDiv = panel.querySelector('#qr-warning');
    const analyzeBtn = panel.querySelector('#qr-analyze-btn');
    
    if (statusEl) statusEl.style.display = 'flex';
    if (statusEl?.querySelector('span')) statusEl.querySelector('span').textContent = 'Click on a QR code image...';
    if (resultEl) resultEl.classList.remove('visible');
    if (hintEl) hintEl.style.display = 'block';
    if (uploadEl) uploadEl.style.display = 'block';
    if (warningDiv) warningDiv.style.display = 'none';
    if (analyzeBtn) {
      analyzeBtn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg> Analyze`;
      analyzeBtn.disabled = false;
      analyzeBtn.style.opacity = '1';
    }
    currentDecodedContent = null;
  }

  function showResult(content, isError = false) {
    if (!panel) return;
    
    const statusEl = panel.querySelector('#qr-status');
    const hintEl = panel.querySelector('#qr-hint');
    const uploadEl = panel.querySelector('#qr-upload');
    const resultDiv = panel.querySelector('#qr-result');
    const warningDiv = panel.querySelector('#qr-warning');
    const warningText = panel.querySelector('#qr-warning-text');
    const contentDiv = panel.querySelector('#qr-content');
    const analyzeBtn = panel.querySelector('#qr-analyze-btn');
    
    if (statusEl) statusEl.style.display = 'none';
    if (hintEl) hintEl.style.display = 'none';
    if (uploadEl) uploadEl.style.display = 'none';
    if (warningDiv) warningDiv.style.display = 'none';
    
    if (!resultDiv || !contentDiv) return;
    
    if (isError) {
      if (warningDiv && warningText) {
        warningDiv.style.display = 'flex';
        warningDiv.className = 'qr-scanner-warning level-high';
        warningText.textContent = content;
      }
      contentDiv.textContent = 'No content decoded';
      currentDecodedContent = null;
      if (analyzeBtn) analyzeBtn.style.display = 'none';
    } else {
      // Extract URL from potentially messy content
      const extractedUrl = extractUrl(content);
      currentDecodedContent = extractedUrl;
      
      // Check if it's a URL
      let isUrl = false;
      try {
        new URL(extractedUrl);
        isUrl = true;
      } catch (e) {}
      
      if (isUrl) {
        contentDiv.innerHTML = `<a href="${escapeHtml(extractedUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(extractedUrl)}</a>`;
        if (analyzeBtn) analyzeBtn.style.display = 'flex';
      } else {
        contentDiv.textContent = extractedUrl;
        if (analyzeBtn) analyzeBtn.style.display = 'none';
      }
    }
    
    resultDiv.classList.add('visible');
    
    chrome.storage.local.set({ 
      qrScanResult: {
        action: 'scanResult',
        success: !isError,
        data: isError ? null : currentDecodedContent,
        error: isError ? content : null,
        timestamp: Date.now()
      }
    });
  }

  function analyzeCurrentUrl() {
    if (!panel || !currentDecodedContent) return;
    
    const warningDiv = panel.querySelector('#qr-warning');
    const warningText = panel.querySelector('#qr-warning-text');
    const analyzeBtn = panel.querySelector('#qr-analyze-btn');
    
    if (!warningDiv || !warningText) return;
    
    const analysis = analyzeUrl(currentDecodedContent);
    warningDiv.style.display = 'flex';
    
    if (analysis.warnings.length > 0) {
      warningDiv.className = `qr-scanner-warning level-${analysis.riskLevel}`;
      warningText.textContent = analysis.warnings.join('. ') + '.';
    } else {
      warningDiv.className = 'qr-scanner-warning level-low';
      warningText.textContent = 'No obvious security issues detected.';
    }
    
    if (analyzeBtn) {
      analyzeBtn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg> Analyzed`;
      analyzeBtn.disabled = true;
      analyzeBtn.style.opacity = '0.6';
    }
  }

  function startScanning() {
    if (isScanning) {
      if (panel) panel.style.display = 'block';
      return;
    }
    isScanning = true;
    chrome.storage.local.remove('qrScanResult');
    
    overlay = document.createElement('div');
    overlay.className = 'qr-scanner-overlay';
    document.body.appendChild(overlay);
    
    createPanel();
    
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) cancelScanning();
    });
    
    activateImageSelection();
    document.addEventListener('keydown', handleEscape);
  }

  function activateImageSelection() {
    document.querySelectorAll('img, [style*="background-image"], canvas, svg').forEach(img => {
      img.classList.add('qr-scanner-highlight');
      img.addEventListener('click', handleImageClick, { once: true });
    });
  }

  function deactivateImageSelection() {
    document.querySelectorAll('.qr-scanner-highlight').forEach(el => {
      el.classList.remove('qr-scanner-highlight');
      el.removeEventListener('click', handleImageClick);
    });
  }

  window.__qrScannerStartScan = startScanning;

  function handleEscape(e) {
    if (e.key === 'Escape') cancelScanning();
  }

  function cancelScanning() {
    isScanning = false;
    if (overlay) { overlay.remove(); overlay = null; }
    if (panel) { panel.remove(); panel = null; }
    deactivateImageSelection();
    removeQrOverlays();
    document.removeEventListener('keydown', handleEscape);
    document.removeEventListener('paste', handlePaste);
  }

  async function handleImageClick(e) {
    e.preventDefault();
    e.stopPropagation();
    
    const element = e.currentTarget;
    deactivateImageSelection();
    if (overlay) { overlay.remove(); overlay = null; }
    
    if (panel) {
      const statusSpan = panel.querySelector('#qr-status span');
      if (statusSpan) statusSpan.textContent = 'Decoding QR code...';
    }
    
    try {
      if (typeof jsQR === 'undefined') {
        showResult('QR decoder not loaded', true);
        return;
      }
      
      const imageData = await getImageData(element);
      if (!imageData) {
        showResult('Could not load image', true);
        return;
      }
      
      const code = jsQR(imageData.data, imageData.width, imageData.height);
      if (code) {
        showResult(code.data);
      } else {
        showResult('No QR code found', true);
      }
    } catch (error) {
      showResult(error.message || 'An error occurred', true);
    }
    
    isScanning = false;
    document.removeEventListener('keydown', handleEscape);
  }

  async function getImageData(element) {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    let imageSrc = null;
    
    if (element instanceof HTMLImageElement) {
      imageSrc = element.src || element.dataset.src || element.getAttribute('data-src');
    } else if (element instanceof HTMLCanvasElement) {
      canvas.width = element.width;
      canvas.height = element.height;
      ctx.drawImage(element, 0, 0);
      return ctx.getImageData(0, 0, canvas.width, canvas.height);
    } else if (element instanceof SVGElement) {
      return await loadSvgToCanvas(element, canvas, ctx);
    }
    
    if (!imageSrc) {
      const bgImage = getComputedStyle(element).backgroundImage;
      if (bgImage && bgImage !== 'none') {
        const urlMatch = bgImage.match(/url\(["']?([^"')]+)["']?\)/);
        if (urlMatch) imageSrc = urlMatch[1];
      }
    }
    
    if (!imageSrc) {
      const nestedImg = element.querySelector('img');
      if (nestedImg) imageSrc = nestedImg.src || nestedImg.dataset.src;
    }
    
    if (imageSrc) return await loadImageToCanvas(imageSrc, canvas, ctx);
    return null;
  }

  async function loadImageToCanvas(src, canvas, ctx) {
    const tryLoad = (withCors) => new Promise((res, rej) => {
      const img = new Image();
      if (withCors) img.crossOrigin = 'anonymous';
      img.onload = () => {
        try {
          canvas.width = img.width;
          canvas.height = img.height;
          ctx.drawImage(img, 0, 0);
          res(ctx.getImageData(0, 0, canvas.width, canvas.height));
        } catch (e) { rej(e); }
      };
      img.onerror = () => rej(new Error('Failed'));
      img.src = src;
    });
    
    try { return await tryLoad(true); } catch (e) {}
    try { return await tryLoad(false); } catch (e) {}
    try { return await fetchImageViaBackground(src); } catch (e) {}
    throw new Error('Cannot load image. Try "Scan Visible Page" or upload instead.');
  }

  async function fetchImageViaBackground(src) {
    const result = await chrome.runtime.sendMessage({ action: 'fetchImage', url: src });
    if (!result?.success) throw new Error(result?.error || 'Failed');
    
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        canvas.width = img.width;
        canvas.height = img.height;
        ctx.drawImage(img, 0, 0);
        try { resolve(ctx.getImageData(0, 0, canvas.width, canvas.height)); }
        catch (e) { reject(e); }
      };
      img.onerror = () => reject(new Error('Failed'));
      img.src = result.dataUrl;
    });
  }

  function loadSvgToCanvas(svgElement, canvas, ctx) {
    return new Promise((resolve, reject) => {
      const svgData = new XMLSerializer().serializeToString(svgElement);
      const svgBlob = new Blob([svgData], { type: 'image/svg+xml;charset=utf-8' });
      const url = URL.createObjectURL(svgBlob);
      const img = new Image();
      img.onload = () => {
        canvas.width = img.width || 200;
        canvas.height = img.height || 200;
        ctx.drawImage(img, 0, 0);
        URL.revokeObjectURL(url);
        try { resolve(ctx.getImageData(0, 0, canvas.width, canvas.height)); }
        catch (e) { reject(new Error('Cannot access SVG')); }
      };
      img.onerror = () => { URL.revokeObjectURL(url); reject(new Error('Failed')); };
      img.src = url;
    });
  }

  async function scanVisiblePage() {
    if (!panel) return;
    
    const statusEl = panel.querySelector('#qr-status');
    const statusSpan = statusEl?.querySelector('span');
    const uploadEl = panel.querySelector('#qr-upload');
    
    if (statusEl) statusEl.style.display = 'flex';
    if (statusSpan) statusSpan.textContent = 'Capturing screen...';
    if (uploadEl) uploadEl.style.display = 'none';
    
    if (panel) panel.style.display = 'none';
    if (overlay) overlay.style.display = 'none';
    
    await new Promise(resolve => setTimeout(resolve, 100));
    
    try {
      const captureResult = await chrome.runtime.sendMessage({ action: 'captureVisibleTab' });
      if (panel) panel.style.display = 'block';
      
      if (!captureResult?.success) {
        showResult(captureResult?.error || 'Failed to capture', true);
        return;
      }
      
      if (statusSpan) statusSpan.textContent = 'Scanning for QR codes...';
      
      // Scan locally using jsQR
      const codes = await scanImageForQr(captureResult.dataUrl);
      
      if (codes.length === 0) {
        showResult('No QR codes found on page', true);
        return;
      }
      
      createQrOverlays(codes);
      if (statusSpan) statusSpan.textContent = `Found ${codes.length} QR code${codes.length > 1 ? 's' : ''} - click to view`;
      if (uploadEl) uploadEl.style.display = 'block';
      
    } catch (error) {
      if (panel) panel.style.display = 'block';
      showResult(error.message || 'Failed to scan', true);
    }
  }

  function scanImageForQr(dataUrl) {
    return new Promise((resolve) => {
      const img = new Image();
      img.onload = () => {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        canvas.width = img.width;
        canvas.height = img.height;
        ctx.drawImage(img, 0, 0);
        
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(imageData.data, imageData.width, imageData.height);
        
        if (code) {
          resolve([{
            data: code.data,
            location: {
              x: code.location.topLeftCorner.x,
              y: code.location.topLeftCorner.y,
              width: code.location.bottomRightCorner.x - code.location.topLeftCorner.x,
              height: code.location.bottomRightCorner.y - code.location.topLeftCorner.y
            },
            imageWidth: img.width,
            imageHeight: img.height
          }]);
        } else {
          resolve([]);
        }
      };
      img.onerror = () => resolve([]);
      img.src = dataUrl;
    });
  }

  function createQrOverlays(codes) {
    removeQrOverlays();
    
    codes.forEach((code) => {
      const scaleX = window.innerWidth / code.imageWidth;
      const scaleY = window.innerHeight / code.imageHeight;
      
      const overlayEl = document.createElement('div');
      overlayEl.className = 'qr-scanner-qr-overlay';
      overlayEl.style.left = `${code.location.x * scaleX}px`;
      overlayEl.style.top = `${code.location.y * scaleY}px`;
      overlayEl.style.width = `${code.location.width * scaleX}px`;
      overlayEl.style.height = `${code.location.height * scaleY}px`;
      
      overlayEl.addEventListener('click', () => {
        showResult(code.data);
        removeQrOverlays();
      });
      
      document.body.appendChild(overlayEl);
      qrOverlays.push(overlayEl);
    });
  }

  function removeQrOverlays() {
    qrOverlays.forEach(el => el.remove());
    qrOverlays = [];
  }

  chrome.runtime.onMessage.addListener((message) => {
    if (message.action === 'startScan') startScanning();
  });

  startScanning();
})();
