// Bitcoin Vulnerability Analyzer - Frontend JavaScript

document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('analyzeForm');
    const autoRecoverForm = document.getElementById('autoRecoverForm');
    const keyAnalysisForm = document.getElementById('keyAnalysisForm');
    const progressSection = document.getElementById('progressSection');
    const progressBar = document.getElementById('progressBar');
    const progressText = document.getElementById('progressText');
    const analyzeBtn = document.getElementById('analyzeBtn');
    
    let progressInterval;
    let currentAddress = '';
    
    // Analysis mode switching
    const modeRadios = document.querySelectorAll('input[name="analysisMode"]');
    const forms = {
        'standard': document.getElementById('analyzeForm'),
        'auto_recover': document.getElementById('autoRecoverForm'),
        'key_analysis': document.getElementById('keyAnalysisForm')
    };
    
    modeRadios.forEach(radio => {
        radio.addEventListener('change', function() {
            // Hide all forms
            Object.values(forms).forEach(form => {
                if (form) form.style.display = 'none';
            });
            
            // Show selected form
            const selectedForm = forms[this.value];
            if (selectedForm) {
                selectedForm.style.display = 'block';
            }
        });
    });
    
    // Form submission handler
    if (form) {
        form.addEventListener('submit', function(e) {
            const addressInput = document.getElementById('address');
            const address = addressInput.value.trim();
            
            if (!address) {
                e.preventDefault();
                showAlert('Please enter a Bitcoin address', 'error');
                return;
            }
            
            if (!isValidBitcoinAddress(address)) {
                e.preventDefault();
                showAlert('Please enter a valid Bitcoin address', 'error');
                return;
            }
            
            // Start progress monitoring
            currentAddress = address;
            startProgressMonitoring();
        });
    }
    
    function startProgressMonitoring() {
        // Show progress section
        progressSection.style.display = 'block';
        analyzeBtn.disabled = true;
        analyzeBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Analyzing...';
        
        // Reset progress
        updateProgress(0, 'Starting analysis...');
        
        // Start polling for progress
        progressInterval = setInterval(function() {
            fetch(`/analyze_progress/${encodeURIComponent(currentAddress)}`)
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        clearInterval(progressInterval);
                        showAlert('Error monitoring progress: ' + data.error, 'error');
                        resetForm();
                        return;
                    }
                    
                    updateProgressFromData(data);
                })
                .catch(error => {
                    console.error('Progress monitoring error:', error);
                    // Continue monitoring - might be temporary network issue
                });
        }, 1000);
        
        // Stop monitoring after reasonable timeout (5 minutes)
        setTimeout(function() {
            if (progressInterval) {
                clearInterval(progressInterval);
                resetForm();
            }
        }, 300000);
    }
    
    function updateProgressFromData(data) {
        const stage = data.stage || 'unknown';
        const count = data.count || 0;
        
        switch (stage) {
            case 'fetching':
                updateProgress(25, `Fetching transactions... (${count} found)`);
                break;
            case 'analyzing':
                updateProgress(50 + (count * 0.5), `Analyzing signatures... (${count} processed)`);
                break;
            case 'completed':
                updateProgress(100, 'Analysis complete!');
                clearInterval(progressInterval);
                // Form will redirect automatically
                break;
            default:
                updateProgress(10, 'Initializing...');
        }
    }
    
    function updateProgress(percentage, text) {
        if (progressBar) {
            progressBar.style.width = percentage + '%';
            progressBar.setAttribute('aria-valuenow', percentage);
        }
        
        if (progressText) {
            progressText.textContent = text;
        }
        
        // Add pulse effect when actively analyzing
        if (percentage > 25 && percentage < 100) {
            progressSection.classList.add('analyzing');
        } else {
            progressSection.classList.remove('analyzing');
        }
    }
    
    function resetForm() {
        if (progressInterval) {
            clearInterval(progressInterval);
            progressInterval = null;
        }
        
        progressSection.style.display = 'none';
        analyzeBtn.disabled = false;
        analyzeBtn.innerHTML = '<i class="fas fa-play me-2"></i>Start Analysis';
        progressSection.classList.remove('analyzing');
        currentAddress = '';
    }
    
    function isValidBitcoinAddress(address) {
        // Basic validation for Bitcoin addresses
        if (!address || typeof address !== 'string') {
            return false;
        }
        
        // Legacy addresses (P2PKH and P2SH)
        if (address.match(/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/)) {
            return true;
        }
        
        // Bech32 addresses (P2WPKH and P2WSH)
        if (address.match(/^(bc1|tb1)[a-z0-9]{39,59}$/)) {
            return true;
        }
        
        return false;
    }
    
    function showAlert(message, type = 'info') {
        // Create alert element
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type === 'error' ? 'danger' : type} alert-dismissible fade show`;
        alertDiv.innerHTML = `
            <i class="fas fa-${type === 'error' ? 'exclamation-triangle' : 'info-circle'} me-2"></i>
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        // Insert at top of container
        const container = document.querySelector('.container');
        const firstCard = container.querySelector('.card');
        container.insertBefore(alertDiv, firstCard);
        
        // Auto-dismiss after 5 seconds
        setTimeout(function() {
            if (alertDiv && alertDiv.parentNode) {
                alertDiv.remove();
            }
        }, 5000);
    }
});

// Copy to clipboard functionality
function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    if (!element) {
        return;
    }
    
    // Select and copy text
    element.select();
    element.setSelectionRange(0, 99999); // For mobile devices
    
    try {
        document.execCommand('copy');
        
        // Show success feedback
        const button = element.nextElementSibling;
        if (button) {
            const originalHTML = button.innerHTML;
            button.innerHTML = '<i class="fas fa-check text-success"></i>';
            
            setTimeout(function() {
                button.innerHTML = originalHTML;
            }, 2000);
        }
        
        // Show toast notification if available
        showToast('Copied to clipboard!', 'success');
        
    } catch (err) {
        console.error('Failed to copy text: ', err);
        showToast('Failed to copy text', 'error');
    }
}

// Toast notification function
function showToast(message, type = 'info') {
    // Create toast container if it doesn't exist
    let toastContainer = document.getElementById('toast-container');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.id = 'toast-container';
        toastContainer.className = 'position-fixed top-0 end-0 p-3';
        toastContainer.style.zIndex = '1055';
        document.body.appendChild(toastContainer);
    }
    
    // Create toast element
    const toastId = 'toast-' + Date.now();
    const toast = document.createElement('div');
    toast.id = toastId;
    toast.className = 'toast align-items-center text-white bg-' + (type === 'error' ? 'danger' : 'success') + ' border-0';
    toast.setAttribute('role', 'alert');
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                <i class="fas fa-${type === 'error' ? 'exclamation-triangle' : 'check'} me-2"></i>
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;
    
    toastContainer.appendChild(toast);
    
    // Initialize and show toast
    const bsToast = new bootstrap.Toast(toast, {
        autohide: true,
        delay: 3000
    });
    bsToast.show();
    
    // Remove toast element after it's hidden
    toast.addEventListener('hidden.bs.toast', function() {
        toast.remove();
    });
}

// Format transaction IDs for better display
function formatTxId(txid) {
    if (!txid || txid.length < 16) {
        return txid;
    }
    return txid.substring(0, 8) + '...' + txid.substring(txid.length - 8);
}

// Add loading state to external links
document.addEventListener('click', function(e) {
    if (e.target.matches('a[target="_blank"]') || e.target.closest('a[target="_blank"]')) {
        const link = e.target.matches('a') ? e.target : e.target.closest('a');
        const originalHTML = link.innerHTML;
        link.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
        
        setTimeout(function() {
            link.innerHTML = originalHTML;
        }, 1000);
    }
});

// Auto-refresh functionality for results page
if (window.location.pathname.includes('/results') || document.querySelector('.vulnerability-card')) {
    // Add warning about private key security
    const privateKeyInputs = document.querySelectorAll('input[value*="0x"]');
    privateKeyInputs.forEach(function(input) {
        input.addEventListener('focus', function() {
            showToast('Warning: Handle private keys securely!', 'warning');
        });
    });
}

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Ctrl+Enter to submit form
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        const form = document.getElementById('analyzeForm');
        if (form && !analyzeBtn.disabled) {
            form.submit();
        }
    }
    
    // Escape to cancel analysis (if supported)
    if (e.key === 'Escape' && progressInterval) {
        if (confirm('Cancel the current analysis?')) {
            resetForm();
        }
    }
});

// Prevent form resubmission on page refresh
if (performance.navigation.type === performance.navigation.TYPE_RELOAD) {
    const form = document.getElementById('analyzeForm');
    if (form) {
        form.reset();
    }
}
