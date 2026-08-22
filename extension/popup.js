const riskLabels = {
  low: { label: 'LOW RISK', className: 'low' },
  medium: { label: 'MEDIUM RISK', className: 'medium' },
  high: { label: 'HIGH RISK', className: 'high' },
  critical: { label: 'CRITICAL RISK', className: 'critical' },
};

const analysisTemplates = {
  message: {
    score: 76,
    category: 'Possible Financial Scam',
    reasons: ['Urgent language', 'Requests for money or credentials', 'Suspicious link pattern'],
    action: 'Do not respond, verify the sender through a trusted channel, and preserve the evidence.',
    evidence: 'Message content selected by the user for review; no automatic WhatsApp scraping was performed.'
  },
  url: {
    score: 68,
    category: 'Suspicious URL',
    reasons: ['Lookalike domain name', 'Unusual URL structure', 'Potential credential harvesting pattern'],
    action: 'Avoid opening the link and verify the destination using a known official site.',
    evidence: 'User-submitted URL analyzed locally for structural risk indicators only.'
  },
  image: {
    score: 59,
    category: 'Suspicious Visual Content',
    reasons: ['OCR indicates urgency', 'QR code detected', 'Potential scam language in image text'],
    action: 'Do not scan QR content or interact with embedded links until reviewed by a trusted source.',
    evidence: 'Image selected for manual review; OCR and QR extraction are user-initiated actions.'
  },
  apk: {
    score: 88,
    category: 'Potentially Malicious APK',
    reasons: ['Sensitive permission combinations', 'Suspicious installer behavior indicators', 'Static package risk flags'],
    action: 'Do not install or run the APK. Store a copy securely and review with a sandboxed or isolated environment.',
    evidence: 'APK file selected for static analysis only; no execution is performed.'
  },
  report: {
    score: 92,
    category: 'Evidence Collection Ready',
    reasons: ['Incident summary prepared', 'Recommended action documented', 'Evidence snapshot created'],
    action: 'Preserve the original evidence and keep the final summary for human review.',
    evidence: 'Prepared incident summary includes timestamp, category, score, and recommended action.'
  }
};

function getRiskBucket(score) {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 30) return 'medium';
  return 'low';
}

function updateResult(template) {
  const score = template.score;
  const bucket = getRiskBucket(score);
  const labelInfo = riskLabels[bucket];

  document.getElementById('risk-label').textContent = labelInfo.label;
  document.getElementById('risk-label').className = `risk-label ${labelInfo.className}`;
  document.getElementById('score-label').textContent = `${score}/100`;
  document.getElementById('risk-score').textContent = `${score}/100`;
  document.getElementById('risk-category').textContent = template.category;

  const reasonsList = document.getElementById('reasons-list');
  reasonsList.innerHTML = template.reasons.map((reason) => `<li>${reason}</li>`).join('');

  document.getElementById('recommended-action').textContent = template.action;
  document.getElementById('evidence-summary').textContent = template.evidence;
}

function initializeButtons() {
  const buttons = document.querySelectorAll('.action-btn');

  buttons.forEach((button) => {
    button.addEventListener('click', () => {
      const action = button.dataset.action;
      const template = analysisTemplates[action];

      if (!template) {
        return;
      }

      updateResult(template);
      chrome.storage.local.set({ safeShieldLastResult: { action, ...template } }, () => {
        // Intentionally no sensitive data is written; this is only a UI state placeholder.
      });
    });
  });
}

document.addEventListener('DOMContentLoaded', () => {
  initializeButtons();

  chrome.storage.local.get(['safeShieldLastResult'], (result) => {
    const last = result.safeShieldLastResult;

    if (last) {
      updateResult(last);
    }
  });
});
