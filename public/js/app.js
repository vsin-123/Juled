// App state
const appState = {
    aiSettings: null,
    currentProvider: null,
    editingProvider: null
};

// API endpoints
const API = {
    base: window.location.origin,
    async request(path, options = {}) {
        try {
            const response = await fetch(`${API.base}${path}`, {
                headers: {
                    'Content-Type': 'application/json',
                    ...options.headers
                },
                ...options
            });
            
            if (!response.ok) {
                const error = await response.json().catch(() => ({ error: 'Request failed' }));
                throw new Error(error.error || `HTTP ${response.status}`);
            }
            
            return await response.json();
        } catch (error) {
            console.error('API request failed:', error);
            throw error;
        }
    },
    
    // AI Settings
    getAISettings() {
        return this.request('/api/ai/settings');
    },
    
    updateAISettings(settings) {
        return this.request('/api/ai/settings', {
            method: 'PUT',
            body: JSON.stringify({ settings })
        });
    },
    
    // Providers
    getProvider(name) {
        return this.request(`/api/ai/providers/${name}`);
    },
    
    addProvider(config) {
        return this.request('/api/ai/providers', {
            method: 'POST',
            body: JSON.stringify(config)
        });
    },
    
    removeProvider(name) {
        return this.request(`/api/ai/providers/${name}`, {
            method: 'DELETE'
        });
    },
    
    validateProvider(config) {
        return this.request('/api/ai/providers/validate', {
            method: 'POST',
            body: JSON.stringify(config)
        });
    },
    
    // Usage
    getUsage() {
        return this.request('/api/ai/usage');
    },
    
    getCosts() {
        return this.request('/api/ai/costs');
    },
    
    clearCache() {
        return this.request('/api/ai/cache', {
            method: 'DELETE'
        });
    }
};

// Toast notifications
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <i class="fas ${getToastIcon(type)}"></i>
        <span>${message}</span>
    `;
    
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => container.removeChild(toast), 300);
    }, 5000);
}

function getToastIcon(type) {
    const icons = {
        success: 'fa-check-circle',
        error: 'fa-exclamation-circle',
        warning: 'fa-exclamation-triangle',
        info: 'fa-info-circle'
    };
    return icons[type] || icons.info;
}

// Tab management
function initTabs() {
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabContents = document.querySelectorAll('.tab-content');
    
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const targetTab = button.getAttribute('data-tab');
            
            // Remove active class from all buttons and contents
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabContents.forEach(content => content.classList.remove('active'));
            
            // Add active class to clicked button and corresponding content
            button.classList.add('active');
            document.getElementById(targetTab)?.classList.add('active');
            
            // Load tab-specific data
            if (targetTab === 'ai-providers') {
                loadProviders();
            } else if (targetTab === 'usage') {
                loadUsageData();
            }
        });
    });
}

// Provider management
async function loadProviders() {
    try {
        const settings = await API.getAISettings();
        const container = document.getElementById('providers-list');
        
        if (settings.providers.length === 0) {
            container.innerHTML = `
                <div style="grid-column: 1 / -1; text-align: center; padding: 2rem; color: var(--text-secondary);">
                    <i class="fas fa-robot" style="font-size: 3rem; margin-bottom: 1rem; opacity: 0.5;"></i>
                    <p>No AI providers configured</p>
                    <p style="font-size: 0.875rem;">Add an AI provider to get started with intelligent security analysis.</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = settings.providers.map(provider => `
            <div class="provider-card">
                <div class="provider-header">
                    <div>
                        <div class="provider-name">${provider.name}</div>
                        <div class="provider-type">${provider.type}</div>
                    </div>
                </div>
                
                <div class="provider-status">
                    <span class="indicator ${!provider.enabled ? 'inactive' : ''}"></span>
                    <span>${provider.enabled ? 'Enabled' : 'Disabled'}</span>
                </div>
                
                <div class="provider-details">
                    <div><strong>Model:</strong></div>
                    <div>${provider.model || 'Default'}</div>
                    <div><strong>Max Tokens:</strong></div>
                    <div>${provider.maxTokens || 4000}</div>
                    <div><strong>API Key:</strong></div>
                    <div>${provider.apiKey ? '••••••••' : 'Not set'}</div>
                </div>
                
                <div class="provider-actions">
                    <button class="btn btn-sm btn-info" onclick="viewProviderStats('${provider.name}')">
                        <i class="fas fa-chart-bar"></i> Stats
                    </button>
                    <button class="btn btn-sm btn-secondary" onclick="editProvider('${provider.name}')">
                        <i class="fas fa-edit"></i> Edit
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="removeProvider('${provider.name}')">
                        <i class="fas fa-trash"></i> Delete
                    </button>
                </div>
            </div>
        `).join('');
        
    } catch (error) {
        showToast('Failed to load providers: ' + error.message, 'error');
    }
}

// Usage and cost data
async function loadUsageData() {
    try {
        const [usage, costs] = await Promise.all([
            API.getUsage(),
            API.getCosts()
        ]);
        
        loadUsageStats(usage);
        loadCostData(costs);
    } catch (error) {
        showToast('Failed to load usage data: ' + error.message, 'error');
    }
}

function loadUsageStats(usage) {
    const container = document.getElementById('usage-stats');
    
    if (!usage.providers || Object.keys(usage.providers).length === 0) {
        container.innerHTML = `
            <div style="text-align: center; padding: 2rem; color: var(--text-secondary);">
                <i class="fas fa-chart-line" style="font-size: 3rem; margin-bottom: 1rem; opacity: 0.5;"></i>
                <p>No usage data available</p>
                <p style="font-size: 0.875rem;">Run some scans to see usage statistics.</p>
            </div>
        `;
        return;
    }
    
    container.innerHTML = Object.entries(usage.providers).map(([name, stats]) => `
        <div class="provider-card" style="margin-bottom: 1rem;">
            <h3 style="margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem;">
                <i class="fas fa-robot"></i> ${name}
            </h3>
            <div class="provider-details">
                <div><strong>Total Requests:</strong></div>
                <div>${stats.totalRequests}</div>
                <div><strong>Total Tokens:</strong></div>
                <div>${stats.totalTokens.toLocaleString()}</div>
                <div><strong>Avg Response Time:</strong></div>
                <div>${stats.averageResponseTime.toFixed(2)}ms</div>
                <div><strong>Errors:</strong></div>
                <div>${stats.errors}</div>
                <div><strong>Last Used:</strong></div>
                <div>${stats.lastUsed ? new Date(stats.lastUsed).toLocaleString() : 'Never'}</div>
            </div>
        </div>
    `).join('');
}

function loadCostData(costs) {
    const container = document.getElementById('cost-summary');
    
    const totalCost = costs.total || 0;
    
    container.innerHTML = `
        <div class="cost-item">
            <div class="cost-amount">$${totalCost.toFixed(4)}</div>
            <div class="cost-label">Total Cost</div>
        </div>
        <div class="cost-item">
            <div class="cost-amount">${Object.keys(costs.costs || {}).length}</div>
            <div class="cost-label">Active Providers</div>
        </div>
    `;
}

// Provider operations
async function viewProviderStats(name) {
    try {
        const provider = await API.getProvider(name);
        showToast(`
            <strong>${name}</strong><br>
            Requests: ${provider.stats.totalRequests}<br>
            Tokens: ${provider.stats.totalTokens}<br>
            Errors: ${provider.stats.errors}
        `, 'info');
    } catch (error) {
        showToast('Failed to load provider stats: ' + error.message, 'error');
    }
}

function editProvider(name) {
    appState.editingProvider = name;
    document.getElementById('modal-title').textContent = 'Edit AI Provider';
    // TODO: Populate form with existing data
    openProviderModal();
}

async function removeProvider(name) {
    if (!confirm(`Are you sure you want to remove provider "${name}"?`)) {
        return;
    }
    
    try {
        await API.removeProvider(name);
        showToast(`Provider "${name}" removed successfully`, 'success');
        loadProviders();
    } catch (error) {
        showToast('Failed to remove provider: ' + error.message, 'error');
    }
}

// Provider modal
function openProviderModal(provider = null) {
    const modal = document.getElementById('provider-modal');
    const form = document.getElementById('provider-form');
    
    appState.editingProvider = provider?.name || null;
    
    form.reset();
    updateProviderFields();
    
    modal.classList.add('active');
}

function closeProviderModal() {
    const modal = document.getElementById('provider-modal');
    modal.classList.remove('active');
    appState.editingProvider = null;
}

function updateProviderFields() {
    const providerType = document.getElementById('provider-type').value;
    const allFields = document.querySelectorAll('.provider-config');
    
    allFields.forEach(field => {
        const provider = field.getAttribute('data-provider');
        if (provider === providerType) {
            field.style.display = 'block';
            const input = field.querySelector('input, select');
            if (input) {
                input.required = true;
            }
        } else {
            field.style.display = 'none';
            const input = field.querySelector('input, select');
            if (input) {
                input.required = false;
                input.value = '';
            }
        }
    });
}

// Form handlers
function initForms() {
    // Settings form
    const settingsForm = document.getElementById('settings-form');
    settingsForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        await updateSettings();
    });
    
    // Provider form
    const providerForm = document.getElementById('provider-form');
    providerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        await saveProvider();
    });
    
    // Provider type change
    document.getElementById('provider-type').addEventListener('change', updateProviderFields);
    
    // Add provider button
    document.getElementById('add-provider-btn').addEventListener('click', () => {
        document.getElementById('modal-title').textContent = 'Add AI Provider';
        openProviderModal();
    });
    
    // Modal close buttons
    document.querySelectorAll('.modal-close, #cancel-provider').forEach(btn => {
        btn.addEventListener('click', closeProviderModal);
    });
    
    // Clear cache button
    document.getElementById('clear-cache-btn').addEventListener('click', async () => {
        if (confirm('Are you sure you want to clear the AI cache?')) {
            try {
                await API.clearCache();
                showToast('Cache cleared successfully', 'success');
            } catch (error) {
                showToast('Failed to clear cache: ' + error.message, 'error');
            }
        }
    });
    
    // Validate provider button
    document.getElementById('validate-provider').addEventListener('click', validateProviderForm);
}

async function updateSettings() {
    try {
        const form = document.getElementById('settings-form');
        const formData = new FormData(form);
        
        const settings = {
            enabled: formData.get('enabled') === 'on',
            fallbackToStaticRules: formData.get('fallbackToStaticRules') === 'on',
            batchSize: parseInt(formData.get('batchSize')) || 5,
            maxConcurrency: parseInt(formData.get('maxConcurrency')) || 3,
            cacheTtl: (parseInt(formData.get('cacheTtl')) || 24) * 3600 // Convert to seconds
        };
        
        await API.updateAISettings(settings);
        showToast('Settings saved successfully', 'success');
        
        // Update status
        document.getElementById('ai-status').textContent = settings.enabled ? 'Enabled' : 'Disabled';
        document.getElementById('ai-status').className = settings.enabled ? 'status-badge' : 'status-badge inactive';
        
    } catch (error) {
        showToast('Failed to save settings: ' + error.message, 'error');
    }
}

async function saveProvider() {
    try {
        const form = document.getElementById('provider-form');
        const formData = new FormData(form);
        
        const config = {
            type: formData.get('type'),
            name: formData.get('name'),
            model: formData.get('model'),
            maxTokens: parseInt(formData.get('maxTokens')) || 4000,
            temperature: parseFloat(formData.get('temperature')) || 0.1,
            enabled: true
        };
        
        // Add provider-specific fields
        const providerType = formData.get('type');
        if (formData.get('apiKey')) {
            config.apiKey = formData.get('apiKey');
        }
        
        switch (providerType) {
            case 'azure-openai':
                config.apiEndpoint = formData.get('apiEndpoint');
                config.deploymentName = formData.get('deploymentName');
                break;
            case 'ollama':
                config.apiEndpoint = formData.get('apiEndpoint');
                break;
        }
        
        if (appState.editingProvider) {
            // Update existing provider
            // TODO: Implement update API
            showToast('Provider update not implemented yet', 'info');
        } else {
            // Add new provider
            await API.addProvider(config);
            showToast('Provider added successfully', 'success');
        }
        
        closeProviderModal();
        loadProviders();
        
    } catch (error) {
        showToast('Failed to save provider: ' + error.message, 'error');
    }
}

async function validateProviderForm() {
    try {
        const form = document.getElementById('provider-form');
        const formData = new FormData(form);
        
        const config = {
            type: formData.get('type'),
            name: formData.get('name') || 'test-provider',
            model: formData.get('model'),
            maxTokens: parseInt(formData.get('maxTokens')) || 4000,
            temperature: parseFloat(formData.get('temperature')) || 0.1,
            enabled: true
        };
        
        if (formData.get('apiKey')) {
            config.apiKey = formData.get('apiKey');
        }
        
        const providerType = formData.get('type');
        if (providerType === 'azure-openai') {
            config.apiEndpoint = formData.get('apiEndpoint');
            config.deploymentName = formData.get('deploymentName');
        } else if (providerType === 'ollama') {
            config.apiEndpoint = formData.get('apiEndpoint');
        }
        
        const validateBtn = document.getElementById('validate-provider');
        const originalText = validateBtn.innerHTML;
        validateBtn.innerHTML = '<span class="loading"></span> Validating...';
        validateBtn.disabled = true;
        
        try {
            const result = await API.validateProvider(config);
            
            if (result.valid) {
                showToast('Provider configuration is valid!', 'success');
            } else {
                showToast('Provider configuration is invalid: ' + (result.error || 'Unknown error'), 'error');
            }
        } finally {
            validateBtn.innerHTML = originalText;
            validateBtn.disabled = false;
        }
        
    } catch (error) {
        showToast('Validation failed: ' + error.message, 'error');
    }
}

// Load initial data
async function loadInitialData() {
    try {
        const settings = await API.getAISettings();
        appState.aiSettings = settings;
        
        // Update status indicators
        document.getElementById('ai-status').textContent = settings.enabled ? 'Enabled' : 'Disabled';
        document.getElementById('ai-status').className = settings.enabled ? 'status-badge' : 'status-badge inactive';
        
        // Update settings form
        const form = document.getElementById('settings-form');
        form.elements['enabled'].checked = settings.enabled;
        form.elements['fallbackToStaticRules'].checked = settings.fallbackToStaticRules;
        form.elements['batchSize'].value = settings.batchSize || 5;
        form.elements['maxConcurrency'].value = settings.maxConcurrency || 3;
        form.elements['cacheTtl'].value = (settings.cacheTtl || 86400) / 3600; // Convert back to hours
        
    } catch (error) {
        showToast('Failed to load initial data: ' + error.message, 'error');
    }
}

// Initialization
document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initForms();
    loadInitialData();
    loadProviders();
    loadUsageData();
    
    // Close modal on outside click
    document.getElementById('provider-modal').addEventListener('click', (e) => {
        if (e.target.id === 'provider-modal') {
            closeProviderModal();
        }
    });
});

// Export functions for global access
window.viewProviderStats = viewProviderStats;
window.editProvider = editProvider;
window.removeProvider = removeProvider;