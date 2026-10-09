/**
 * CYBERSHIELD MCP HUB - INTERACTIVE SOC WORKBENCH CLIENT
 * Vanilla JavaScript Controller for Tool Execution, Dynamic Forms, and OSINT Visualizer
 */

(function () {
  'use strict';

  // State Management
  const state = {
    skills: [],
    tools: [],
    filteredTools: [],
    activeSkillFilter: 'all',
    activeTool: null,
    searchQuery: '',
    currentOutputTab: 'visual',
    currentView: 'workbench',
    lastExecutionResult: null,
    stealthConfig: null,
  };

  // DOM Elements
  const elements = {
    serverStatusText: document.getElementById('server-status-text'),
    serverStatusPill: document.getElementById('server-status-pill'),
    toolsListContainer: document.getElementById('tools-list-container'),
    skillFiltersContainer: document.getElementById('skill-filters-container'),
    toolSearchInput: document.getElementById('tool-search-input'),
    activeToolHeader: document.getElementById('active-tool-header'),
    activeToolName: document.getElementById('active-tool-name'),
    activeToolSkillBadge: document.getElementById('active-tool-skill-badge'),
    activeToolDescription: document.getElementById('active-tool-description'),
    dynamicToolForm: document.getElementById('dynamic-tool-form'),
    formFieldsGrid: document.getElementById('form-fields-grid'),
    btnExecuteTool: document.getElementById('btn-execute-tool'),
    btnExecText: document.getElementById('btn-exec-text'),
    btnExecIcon: document.getElementById('btn-exec-icon'),
    btnPrefillExample: document.getElementById('btn-prefill-example'),
    btnClearForm: document.getElementById('btn-clear-form'),
    resultStatusPill: document.getElementById('result-status-pill'),
    resultStatusText: document.getElementById('result-status-text'),
    resultDurationBadge: document.getElementById('result-duration-badge'),
    resultDurationMs: document.getElementById('result-duration-ms'),
    btnCopyResult: document.getElementById('btn-copy-result'),
    outputViewVisual: document.getElementById('output-view-visual'),
    outputViewJson: document.getElementById('output-view-json'),
    outputViewRaw: document.getElementById('output-view-raw'),
    outputEmptyState: document.getElementById('output-empty-state'),
    visualResultsFeed: document.getElementById('visual-results-feed'),
    jsonViewerContent: document.getElementById('json-viewer-content'),
    rawViewerContent: document.getElementById('raw-viewer-content'),
    toastContainer: document.getElementById('toast-container'),
    // Views
    viewWorkbench: document.getElementById('view-workbench'),
    viewTimeline: document.getElementById('view-timeline'),
    viewDossier: document.getElementById('view-dossier'),
    tabBtnWorkbench: document.getElementById('tab-btn-workbench'),
    tabBtnTimeline: document.getElementById('tab-btn-timeline'),
    tabBtnDossier: document.getElementById('tab-btn-dossier'),
    // Timeline
    timelineEventsFeed: document.getElementById('timeline-events-feed'),
    timelineSkillFilter: document.getElementById('timeline-skill-filter'),
    btnRefreshTimeline: document.getElementById('btn-refresh-timeline'),
    btnRecordFindingModal: document.getElementById('btn-record-finding-modal'),
    // Dossier
    dossierContentPre: document.getElementById('dossier-content-pre'),
    btnCopyDossier: document.getElementById('btn-copy-dossier'),
    btnDownloadDossier: document.getElementById('btn-download-dossier'),
    // Sidebar Toggle
    toolsSidebar: document.getElementById('tools-sidebar'),
    btnSidebarToggle: document.getElementById('btn-sidebar-toggle'),
    sidebarToggleArrow: document.getElementById('sidebar-toggle-arrow'),
    btnExpandSidebarPill: document.getElementById('btn-expand-sidebar-pill'),
    sidebarBadgeCount: document.getElementById('sidebar-badge-count'),
    // Modal
    findingModalBackdrop: document.getElementById('finding-modal-backdrop'),
    btnCloseFindingModal: document.getElementById('btn-close-finding-modal'),
    btnCancelFinding: document.getElementById('btn-cancel-finding'),
    newFindingForm: document.getElementById('new-finding-form'),
    // Stealth & Onion Node Modal
    btnStealthModal: document.getElementById('btn-stealth-modal'),
    stealthStatusBadge: document.getElementById('stealth-status-badge'),
    stealthModal: document.getElementById('stealth-modal'),
    btnCloseStealthModal: document.getElementById('btn-close-stealth-modal'),
    btnCancelStealth: document.getElementById('btn-cancel-stealth'),
    stealthConfigForm: document.getElementById('stealth-config-form'),
    stealthToggleInput: document.getElementById('stealth-toggle-input'),
    stealthProxyUrl: document.getElementById('stealth-proxy-url'),
    stealthDnsInput: document.getElementById('stealth-dns-input'),
    btnTestTor: document.getElementById('btn-test-tor'),
    stealthStatusCard: document.getElementById('stealth-status-card'),
    stealthIndicatorDot: document.getElementById('stealth-indicator-dot'),
    stealthCardTitle: document.getElementById('stealth-card-title'),
    stealthCardDesc: document.getElementById('stealth-card-desc'),
    stealthIpBanner: document.getElementById('stealth-ip-banner'),
    stealthExitIp: document.getElementById('stealth-exit-ip'),
    stealthTorVerified: document.getElementById('stealth-tor-verified'),
  };

  // Initialize
  async function init() {
    setupEventListeners();
    await fetchServerInfo();
    await fetchStealthStatus();
    await fetchSkillsAndTools();

    // Default select Maigret tool if available, without initial collapse
    const defaultTool = state.tools.find(t => t.name === 'search_username_maigret') || state.tools[0];
    if (defaultTool) {
      selectTool(defaultTool, false);
    }
  }

  // Event Listeners Setup
  function setupEventListeners() {
    // Sidebar Collapse / Expand Toggle
    if (elements.btnSidebarToggle) {
      elements.btnSidebarToggle.addEventListener('click', () => {
        setSidebarCollapsed(!state.sidebarCollapsed);
      });
    }

    if (elements.btnExpandSidebarPill) {
      elements.btnExpandSidebarPill.addEventListener('click', () => {
        setSidebarCollapsed(false);
      });
    }

    // Search input
    elements.toolSearchInput.addEventListener('input', (e) => {
      state.searchQuery = e.target.value.toLowerCase().trim();
      filterAndRenderTools();
    });

    // Keyboard shortcut Ctrl+K / Cmd+K for search
    window.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setSidebarCollapsed(false);
        elements.toolSearchInput.focus();
        elements.toolSearchInput.select();
      } else if (e.altKey && e.key.toLowerCase() === 'm') {
        e.preventDefault();
        setSidebarCollapsed(!state.sidebarCollapsed);
      }
    });

    // Form buttons
    elements.btnPrefillExample.addEventListener('click', prefillExampleData);
    elements.btnClearForm.addEventListener('click', clearFormFields);
    elements.btnExecuteTool.addEventListener('click', executeActiveTool);

    // Output tabs
    document.querySelectorAll('.output-tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const tab = btn.getAttribute('data-output-tab');
        switchOutputTab(tab);
      });
    });

    // Copy result button
    elements.btnCopyResult.addEventListener('click', copyResultToClipboard);

    // View Navigation Tabs
    elements.tabBtnWorkbench.addEventListener('click', () => switchView('workbench'));
    elements.tabBtnTimeline.addEventListener('click', () => {
      switchView('timeline');
      fetchTimeline();
    });
    elements.tabBtnDossier.addEventListener('click', () => {
      switchView('dossier');
      fetchDossierReport();
    });

    // Timeline Controls
    elements.btnRefreshTimeline.addEventListener('click', fetchTimeline);
    elements.timelineSkillFilter.addEventListener('change', fetchTimeline);

    // Finding Modal
    elements.btnRecordFindingModal.addEventListener('click', () => {
      elements.findingModalBackdrop.style.display = 'flex';
    });
    elements.btnCloseFindingModal.addEventListener('click', () => {
      elements.findingModalBackdrop.style.display = 'none';
    });
    elements.btnCancelFinding.addEventListener('click', () => {
      elements.findingModalBackdrop.style.display = 'none';
    });
    elements.newFindingForm.addEventListener('submit', handleSaveFinding);

    // Dossier Actions
    elements.btnCopyDossier.addEventListener('click', () => {
      const text = elements.dossierContentPre.textContent;
      navigator.clipboard.writeText(text);
      showToast('Dossiê copiado para a área de transferência!', 'success');
    });

    elements.btnDownloadDossier.addEventListener('click', () => {
      const text = elements.dossierContentPre.textContent;
      const blob = new Blob([text], { type: 'text/markdown;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `investigation_dossier_${Date.now()}.md`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      showToast('Download do dossiê iniciado!', 'success');
    });

    // Stealth Modal & Onion Node Event Listeners
    if (elements.btnStealthModal) {
      elements.btnStealthModal.addEventListener('click', openStealthModal);
    }
    if (elements.btnCloseStealthModal) {
      elements.btnCloseStealthModal.addEventListener('click', closeStealthModal);
    }
    if (elements.btnCancelStealth) {
      elements.btnCancelStealth.addEventListener('click', closeStealthModal);
    }
    if (elements.stealthConfigForm) {
      elements.stealthConfigForm.addEventListener('submit', handleSaveStealth);
    }
    if (elements.btnTestTor) {
      elements.btnTestTor.addEventListener('click', handleTestTor);
    }

    // Quick presets buttons
    document.querySelectorAll('.btn-preset').forEach(btn => {
      btn.addEventListener('click', () => {
        const presetVal = btn.getAttribute('data-preset');
        if (presetVal && elements.stealthProxyUrl) {
          elements.stealthProxyUrl.value = presetVal;
        }
      });
    });

    // Close modal on backdrop click
    if (elements.stealthModal) {
      elements.stealthModal.addEventListener('click', (e) => {
        if (e.target === elements.stealthModal) {
          closeStealthModal();
        }
      });
    }

    // Expose selectTool globally for click shortcuts
    window.selectToolByName = (name) => {
      const tool = state.tools.find(t => t.name === name);
      if (tool) selectTool(tool);
    };
  }

  // Switch Main Views (Workbench, Timeline, Dossier)
  function switchView(viewName) {
    state.currentView = viewName;
    [elements.viewWorkbench, elements.viewTimeline, elements.viewDossier].forEach(el => el.classList.remove('active-panel'));
    [elements.tabBtnWorkbench, elements.tabBtnTimeline, elements.tabBtnDossier].forEach(el => el.classList.remove('active-btn', 'active'));

    if (viewName === 'workbench') {
      elements.viewWorkbench.classList.add('active-panel');
      elements.tabBtnWorkbench.classList.add('active');
    } else if (viewName === 'timeline') {
      elements.viewTimeline.classList.add('active-panel');
      elements.tabBtnTimeline.classList.add('active');
    } else if (viewName === 'dossier') {
      elements.viewDossier.classList.add('active-panel');
      elements.tabBtnDossier.classList.add('active');
    }
  }

  // Switch Output Sub-Tabs
  function switchOutputTab(tabName) {
    state.currentOutputTab = tabName;
    document.querySelectorAll('.output-tab-btn').forEach(btn => {
      btn.classList.toggle('active', btn.getAttribute('data-output-tab') === tabName);
    });

    [elements.outputViewVisual, elements.outputViewJson, elements.outputViewRaw].forEach(el => el.classList.remove('active'));

    if (tabName === 'visual') elements.outputViewVisual.classList.add('active');
    else if (tabName === 'json') elements.outputViewJson.classList.add('active');
    else if (tabName === 'raw') elements.outputViewRaw.classList.add('active');
  }

  // API: Fetch Server Metadata
  async function fetchServerInfo() {
    try {
      const res = await fetch('/api/info');
      if (!res.ok) throw new Error('Servidor não respondeu.');
      const data = await res.json();
      elements.serverStatusText.textContent = `MCP Hub v${data.version} Online (${data.total_tools} Ferramentas)`;
      elements.serverStatusPill.className = 'status-indicator-pill';
    } catch (err) {
      elements.serverStatusText.textContent = 'Erro ao conectar ao MCP Hub';
      elements.serverStatusPill.style.borderColor = 'var(--rose-danger)';
      elements.serverStatusPill.style.color = 'var(--rose-danger)';
    }
  }

  // API: Fetch Skills & Tools
  async function fetchSkillsAndTools() {
    try {
      const [skillsRes, toolsRes] = await fetchSkillsAndToolsData();
      state.skills = skillsRes.skills || [];
      state.tools = toolsRes.tools || [];
      renderSkillFilters();
      filterAndRenderTools();
    } catch (err) {
      elements.toolsListContainer.innerHTML = `<div class="loading-placeholder">Erro ao carregar ferramentas: ${err.message}</div>`;
    }
  }

  async function fetchSkillsAndToolsData() {
    const [skillsRes, toolsRes] = await Promise.all([
      fetch('/api/skills').then(r => r.json()),
      fetch('/api/tools').then(r => r.json()),
    ]);
    return [skillsRes, toolsRes];
  }

  // Render Skill Filter Pills
  function renderSkillFilters() {
    const totalTools = state.tools.length;
    let html = `
      <button type="button" class="skill-pill ${state.activeSkillFilter === 'all' ? 'active' : ''}" data-skill="all">
        <span>🌐</span> Todas (${totalTools})
      </button>
    `;

    state.skills.forEach(skill => {
      if (skill.id === 'general' && skill.tool_count === 0) return;
      html += `
        <button type="button" class="skill-pill ${state.activeSkillFilter === skill.id ? 'active' : ''}" data-skill="${skill.id}">
          <span>${skill.icon}</span> ${skill.name.split('(')[0].trim()} (${skill.tool_count})
        </button>
      `;
    });

    elements.skillFiltersContainer.innerHTML = html;

    // Filter pill click listeners
    elements.skillFiltersContainer.querySelectorAll('.skill-pill').forEach(btn => {
      btn.addEventListener('click', () => {
        state.activeSkillFilter = btn.getAttribute('data-skill');
        renderSkillFilters();
        filterAndRenderTools();
      });
    });
  }

  const SKILL_SHORT_BADGES = {
    osint_recon: 'OSINT',
    appsec: 'AppSec',
    security_audit: 'SAST',
    threat_intel: 'MITRE',
    cloud_container: 'Cloud',
    incident_response: 'DFIR',
    rea: 'REA',
    memory: 'Memory',
    general: 'Core',
  };

  // Filter & Render Tool List
  function filterAndRenderTools() {
    state.filteredTools = state.tools.filter(tool => {
      const matchesSkill = state.activeSkillFilter === 'all' || tool.skill === state.activeSkillFilter;
      const matchesSearch = !state.searchQuery ||
        tool.name.toLowerCase().includes(state.searchQuery) ||
        (tool.description && tool.description.toLowerCase().includes(state.searchQuery)) ||
        tool.skill.toLowerCase().includes(state.searchQuery);
      return matchesSkill && matchesSearch;
    });

    if (state.filteredTools.length === 0) {
      elements.toolsListContainer.innerHTML = `
        <div class="loading-placeholder">Nenhuma ferramenta encontrada com os filtros atuais.</div>
      `;
      return;
    }

    let html = '';
    state.filteredTools.forEach(tool => {
      const isActive = state.activeTool && state.activeTool.name === tool.name;
      const shortBadge = SKILL_SHORT_BADGES[tool.skill] || tool.skill.toUpperCase();
      const cardDesc = tool.short_description || cleanDocstring(tool.description);
      html += `
        <div class="tool-card-item ${isActive ? 'active' : ''}" data-tool-name="${tool.name}" title="${tool.name} [${shortBadge}]">
          <div class="tool-card-header-row">
            <span class="tool-item-name">${tool.name}</span>
            <span class="tool-skill-tag" style="background:${tool.skill_color}1f; color:${tool.skill_color}; border: 1px solid ${tool.skill_color}44;">
              <span class="skill-mini-icon">${tool.skill_icon || '⚡'}</span>
              <span class="skill-name-text">${shortBadge}</span>
            </span>
          </div>
          <p class="tool-item-desc">${escapeHtml(cardDesc)}</p>
        </div>
      `;
    });

    elements.toolsListContainer.innerHTML = html;

    // Card click events
    elements.toolsListContainer.querySelectorAll('.tool-card-item').forEach(card => {
      card.addEventListener('click', () => {
        const toolName = card.getAttribute('data-tool-name');
        const tool = state.tools.find(t => t.name === toolName);
        if (tool) selectTool(tool, true);
      });
    });
  }

  function cleanDocstring(text) {
    if (!text) return '';
    return text.split('\n\n')[0].replace(/\n/g, ' ').trim();
  }

  // Sidebar Collapse Controller
  function setSidebarCollapsed(collapsed) {
    state.sidebarCollapsed = collapsed;
    if (elements.toolsSidebar) {
      elements.toolsSidebar.classList.toggle('collapsed', collapsed);
    }
    if (elements.sidebarToggleArrow) {
      elements.sidebarToggleArrow.textContent = collapsed ? '▶' : '◀';
    }
    if (elements.btnSidebarToggle) {
      elements.btnSidebarToggle.title = collapsed ? 'Expandir Menu Lateral (Alt+M)' : 'Recolher Menu Lateral (Alt+M)';
    }
  }

  // Select Active Tool
  function selectTool(tool, autoCollapse = true) {
    state.activeTool = tool;

    // Update active styles on list
    elements.toolsListContainer.querySelectorAll('.tool-card-item').forEach(c => {
      c.classList.toggle('active', c.getAttribute('data-tool-name') === tool.name);
    });

    const shortBadge = SKILL_SHORT_BADGES[tool.skill] || tool.skill.toUpperCase();

    // Update Header
    elements.activeToolName.textContent = tool.name;
    elements.activeToolSkillBadge.textContent = `${tool.skill_icon || '🛡️'} ${shortBadge}`;
    elements.activeToolSkillBadge.style.borderColor = `${tool.skill_color}66`;
    elements.activeToolSkillBadge.style.color = tool.skill_color;
    elements.activeToolDescription.textContent = tool.description || 'Sem descrição detalhada.';

    // Automatically collapse sidebar on selection to maximize workbench workspace
    if (autoCollapse) {
      setSidebarCollapsed(true);
    }

    // Render Dynamic Form
    renderDynamicForm(tool);
  }

  // Dynamic Parameter Form Generator
  function renderDynamicForm(tool) {
    const schema = tool.input_schema || {};
    const properties = schema.properties || {};
    const requiredFields = schema.required || [];
    const paramDescs = tool.param_descriptions || {};

    const propKeys = Object.keys(properties);

    if (propKeys.length === 0) {
      elements.formFieldsGrid.innerHTML = `
        <div class="empty-params-note" style="color: var(--text-muted); font-size: 13px; padding: 12px 0;">
          ⚡ Esta ferramenta não requer nenhum parâmetro obrigatório. Pode ser executada diretamente.
        </div>
      `;
      return;
    }

    let fieldsHtml = '';

    propKeys.forEach(propName => {
      const propDef = properties[propName] || {};
      const isRequired = requiredFields.includes(propName);
      const title = propDef.title || propName;
      const typeStr = getParamTypeString(propDef);
      const description = paramDescs[propName] || propDef.description || '';
      const defaultValue = propDef.default !== undefined ? propDef.default : '';
      const placeholderText = description || title;

      fieldsHtml += `
        <div class="form-group" data-param-name="${propName}">
          <div class="form-label-row">
            <label for="param-${propName}" class="form-label">
              ${propName} ${isRequired ? '<span class="required-star">*</span>' : ''}
            </label>
            <span class="param-type-badge">${typeStr}</span>
          </div>
      `;

      // Determine appropriate input widget
      if (typeStr.includes('bool') || propDef.type === 'boolean') {
        const isChecked = defaultValue === true;
        fieldsHtml += `
          <div class="switch-wrapper">
            <label class="toggle-switch">
              <input type="checkbox" id="param-${propName}" name="${propName}" ${isChecked ? 'checked' : ''}>
              <span class="slider-switch"></span>
            </label>
            <span class="switch-label">${description || propName}</span>
          </div>
        `;
      } else if (
        propName.includes('content') ||
        propName.includes('dockerfile') ||
        propName.includes('policy') ||
        propName.includes('description') ||
        propName.includes('summary') ||
        propDef.type === 'string' && (description.length > 80 || propName.includes('template'))
      ) {
        fieldsHtml += `
          <textarea id="param-${propName}" name="${propName}" class="form-textarea" rows="3" placeholder="${escapeHtml(placeholderText)}">${defaultValue ? escapeHtml(String(defaultValue)) : ''}</textarea>
        `;
      } else if (propDef.type === 'integer' || propDef.type === 'number') {
        fieldsHtml += `
          <input type="number" id="param-${propName}" name="${propName}" class="form-input" value="${defaultValue}" placeholder="${escapeHtml(placeholderText)}">
        `;
      } else {
        // Standard text input
        fieldsHtml += `
          <input type="text" id="param-${propName}" name="${propName}" class="form-input" value="${defaultValue ? escapeHtml(String(defaultValue)) : ''}" placeholder="${escapeHtml(placeholderText)}">
        `;
      }

      if (description && !typeStr.includes('bool')) {
        fieldsHtml += `<span class="param-help-text">${escapeHtml(description)}</span>`;
      }

      fieldsHtml += `</div>`;
    });

    elements.formFieldsGrid.innerHTML = fieldsHtml;
  }

  function getParamTypeString(def) {
    if (def.type) return def.type;
    if (def.anyOf) {
      const types = def.anyOf.map(t => t.type).filter(Boolean);
      return types.join(' | ') || 'any';
    }
    return 'string';
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // Pre-fill Example Data
  function prefillExampleData() {
    if (!state.activeTool) return;
    const example = state.activeTool.example_payload || {};
    Object.keys(example).forEach(key => {
      const input = document.getElementById(`param-${key}`);
      if (!input) return;
      if (input.type === 'checkbox') {
        input.checked = Boolean(example[key]);
      } else {
        input.value = typeof example[key] === 'object' ? JSON.stringify(example[key], null, 2) : example[key];
      }
    });
    showToast(`Exemplo preenchido para ${state.activeTool.name}!`, 'success');
  }

  // Clear Form Fields
  function clearFormFields() {
    if (!state.activeTool) return;
    elements.dynamicToolForm.reset();
    showToast('Campos limpos.', 'info');
  }

  // Execute Active Tool
  async function executeActiveTool() {
    if (!state.activeTool) {
      showToast('Nenhuma ferramenta selecionada.', 'error');
      return;
    }

    const tool = state.activeTool;
    const schema = tool.input_schema || {};
    const properties = schema.properties || {};
    const args = {};

    // Collect values from form
    Object.keys(properties).forEach(propName => {
      const input = document.getElementById(`param-${propName}`);
      if (!input) return;

      const propDef = properties[propName] || {};
      const typeStr = getParamTypeString(propDef);

      if (input.type === 'checkbox') {
        args[propName] = input.checked;
      } else {
        const val = input.value.trim();
        if (val !== '') {
          if (typeStr === 'integer') {
            args[propName] = parseInt(val, 10);
          } else if (typeStr === 'number') {
            args[propName] = parseFloat(val);
          } else if (typeStr.includes('array') && val.includes(',')) {
            args[propName] = val.split(',').map(s => s.trim()).filter(Boolean);
          } else {
            args[propName] = val;
          }
        }
      }
    });

    // Update UI to running state
    setRunningState(true);

    try {
      const res = await fetch(`/api/tools/${encodeURIComponent(tool.name)}/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ arguments: args }),
      });

      const data = await res.json();
      state.lastExecutionResult = data;

      // Update timer & status pill
      elements.resultDurationBadge.style.display = 'inline-flex';
      elements.resultDurationMs.textContent = data.duration_ms || '0';

      if (data.success && !data.is_error) {
        setResultPill('Sucesso', 'status-success');
        showToast(`Executado em ${data.duration_ms}ms`, 'success');
      } else {
        setResultPill('Erro / Falha', 'status-error');
        showToast(`Erro na execução da ferramenta`, 'error');
      }

      // Render Outputs across tabs
      renderExecutionOutput(tool, data);
    } catch (err) {
      setResultPill('Falha de Rede', 'status-error');
      showToast(`Erro: ${err.message}`, 'error');
      renderErrorOutput(err);
    } finally {
      setRunningState(false);
    }
  }

  function setRunningState(isRunning) {
    elements.btnExecuteTool.disabled = isRunning;
    if (isRunning) {
      elements.btnExecText.textContent = 'Executando...';
      elements.btnExecIcon.textContent = '⏳';
      setResultPill('Processando...', 'status-running');
      elements.outputEmptyState.style.display = 'none';
      elements.visualResultsFeed.style.display = 'block';
      elements.visualResultsFeed.innerHTML = `
        <div class="loading-placeholder">
          <div class="empty-icon-radar" style="margin: 0 auto 12px auto;">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
              <circle cx="12" cy="12" r="9"/>
              <path d="M12 3v9l6 3"/>
            </svg>
          </div>
          Consultando serviço de segurança e agregando evidências...
        </div>
      `;
    } else {
      elements.btnExecText.textContent = 'Executar Ferramenta';
      elements.btnExecIcon.textContent = '🚀';
    }
  }

  function setResultPill(text, className) {
    elements.resultStatusPill.className = `output-status-pill ${className}`;
    elements.resultStatusText.textContent = text;
  }

  // Render Execution Output in Visual, JSON, and Raw views
  function renderExecutionOutput(tool, payload) {
    const data = payload.data;
    const rawText = payload.raw_text || JSON.stringify(data, null, 2);

    // 1. JSON Viewer
    elements.jsonViewerContent.textContent = JSON.stringify(data, null, 2);

    // 2. Raw Text Viewer
    elements.rawViewerContent.textContent = rawText;

    // 3. Smart Visual View
    elements.outputEmptyState.style.display = 'none';
    elements.visualResultsFeed.style.display = 'block';

    if (tool.name === 'search_username_maigret') {
      renderMaigretVisual(data);
    } else if (tool.name === 'get_maigret_stats') {
      renderMaigretStatsVisual(data);
    } else if (tool.name === 'inspect_http_headers') {
      renderHttpHeadersVisual(data);
    } else if (tool.name === 'inspect_tls_certificate') {
      renderTlsVisual(data);
    } else if (tool.name === 'lookup_dns_records') {
      renderDnsVisual(data);
    } else if (tool.name === 'map_mitre_attack') {
      renderMitreVisual(data);
    } else if (tool.name === 'audit_dockerfile') {
      renderDockerfileVisual(data);
    } else if (tool.name === 'audit_iam_policy') {
      renderIamPolicyVisual(data);
    } else if (tool.name === 'triage_security_incident') {
      renderIncidentTriageVisual(data);
    } else if (tool.name.startsWith('scan_secrets') || tool.name.startsWith('run_sast') || tool.name.startsWith('audit_owasp')) {
      renderSastVisual(data, tool.name);
    } else {
      renderGenericVisual(data, tool);
    }
  }

  function renderErrorOutput(err) {
    elements.outputEmptyState.style.display = 'none';
    elements.visualResultsFeed.style.display = 'block';
    elements.visualResultsFeed.innerHTML = `
      <div class="finding-issue-card severity-critical">
        <div class="finding-title-row">
          <span class="finding-title">Erro durante execução da ferramenta</span>
          <span class="severity-badge badge-critical">Exceção</span>
        </div>
        <p class="finding-detail-text">${escapeHtml(err.message)}</p>
      </div>
    `;
    elements.jsonViewerContent.textContent = JSON.stringify({ error: err.message }, null, 2);
    elements.rawViewerContent.textContent = err.stack || err.message;
  }

  // --- SPECIALIZED VISUAL RENDERERS ---

  // 1. Maigret OSINT Visual View
  function renderMaigretVisual(data) {
    if (!data || typeof data !== 'object') {
      renderGenericVisual(data);
      return;
    }

    const username = data.username || 'alvo';
    const totalFound = data.total_accounts_found || 0;
    const accounts = data.accounts || [];
    const interests = data.inferred_interests_tags || [];
    const summary = data.summary || '';

    let html = `
      <div class="visual-summary-banner">
        <div>
          <div class="summary-headline">🔎 Investigação Maigret: @${escapeHtml(username)}</div>
          <div class="summary-detail">${escapeHtml(summary)}</div>
        </div>
        <div class="summary-count-badge">${totalFound} Contas</div>
      </div>
    `;

    if (interests.length > 0) {
      html += `
        <div class="maigret-tags-row" style="margin: 4px 0;">
          <strong style="font-size: 11px; color: var(--text-muted); align-self: center;">INTERESSES / TAGS:</strong>
          ${interests.map(t => `<span class="maigret-tag-chip" style="background: rgba(0, 240, 255, 0.1); color: var(--cyan-neon);">${escapeHtml(t)}</span>`).join('')}
        </div>
      `;
    }

    if (accounts.length === 0) {
      html += `
        <div class="finding-issue-card severity-low" style="margin-top: 10px;">
          <p class="finding-detail-text">Nenhuma conta pública confirmada nos sites escaneados para o usuário '@${escapeHtml(username)}'.</p>
        </div>
      `;
    } else {
      html += `<div class="maigret-accounts-grid">`;
      accounts.forEach(acc => {
        const metadata = acc.metadata || {};
        const avatarUrl = metadata.image;
        const fullname = metadata.fullname || '';
        const site = acc.site || 'Site';
        const url = acc.url || '#';
        const tags = acc.tags || [];

        html += `
          <div class="maigret-account-card">
            <div class="maigret-card-top">
              ${avatarUrl ? `
                <img src="${escapeHtml(avatarUrl)}" alt="Avatar" class="maigret-avatar" onerror="this.style.display='none';">
              ` : `
                <div class="maigret-avatar-placeholder">${site.slice(0, 2).toUpperCase()}</div>
              `}
              <div class="maigret-info">
                <div class="maigret-site-title">
                  <span>${escapeHtml(site)}</span>
                  ${acc.alexa_rank ? `<span style="font-size: 10px; color: var(--text-muted); font-weight: normal;">#${acc.alexa_rank}</span>` : ''}
                </div>
                ${fullname ? `<div class="maigret-fullname">${escapeHtml(fullname)}</div>` : ''}
                ${metadata.created_at ? `<div style="font-size: 10px; color: var(--text-muted);">Registrado: ${escapeHtml(metadata.created_at)}</div>` : ''}
              </div>
            </div>

            ${tags.length > 0 ? `
              <div class="maigret-tags-row">
                ${tags.map(t => `<span class="maigret-tag-chip">${escapeHtml(t)}</span>`).join('')}
              </div>
            ` : ''}

            <div class="maigret-card-footer">
              <span class="maigret-meta-metrics">
                ${metadata.follower_count ? `👥 ${metadata.follower_count} seguidores` : ''}
              </span>
              <a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer" class="maigret-link-btn">
                Acessar Perfil ↗
              </a>
            </div>
          </div>
        `;
      });
      html += `</div>`;
    }

    if (data.persisted_report_file) {
      html += `
        <div style="font-size: 11px; color: var(--text-muted); margin-top: 10px; font-family: var(--font-mono);">
          💾 Dossiê JSON salvo em: ${escapeHtml(data.persisted_report_file)}
        </div>
      `;
    }

    elements.visualResultsFeed.innerHTML = html;
  }

  // 2. Maigret Database Stats Visual
  function renderMaigretStatsVisual(data) {
    const totalSites = data.total_supported_sites || 8077;
    const topTags = data.top_categories_tags || [];
    let html = `
      <div class="visual-summary-banner">
        <div>
          <div class="summary-headline">Base de Dados Maigret OSINT</div>
          <div class="summary-detail">Cobertura global de redes sociais, fóruns, blogs e plataformas técnicas.</div>
        </div>
        <div class="summary-count-badge">${totalSites} Sites</div>
      </div>
      <h4 style="font-size: 13px; font-weight: 700; color: #fff; margin: 12px 0 6px 0;">Principais Categorias & Tags Suportadas:</h4>
      <div class="maigret-tags-row">
        ${topTags.map(t => `<span class="maigret-tag-chip" style="background: rgba(0,240,255,0.1); color: var(--cyan-neon); font-size: 11px; padding: 4px 8px;">${escapeHtml(t.tag || String(t))}</span>`).join('')}
      </div>
    `;
    elements.visualResultsFeed.innerHTML = html;
  }

  // 3. HTTP Security Headers Visual
  function renderHttpHeadersVisual(data) {
    const score = data.security_score_percentage || 0;
    const missing = data.missing_security_headers || [];
    const present = data.present_security_headers || {};

    let html = `
      <div class="score-card-hero">
        <div class="score-circle-wrapper" style="--score-pct: ${score};">
          <div class="score-inner-text">${score}%</div>
        </div>
        <div class="score-meta">
          <h4>Postura de Cabeçalhos HTTP (${data.url || ''})</h4>
          <p>Status HTTP: <strong>${data.status_code || 200}</strong> | Proteções presentes: ${Object.keys(present).length}</p>
        </div>
      </div>
    `;

    if (missing.length > 0) {
      html += `<h4 style="font-size: 13px; font-weight: 700; color: #fff; margin: 14px 0 8px 0;">Cabeçalhos de Segurança Ausentes (${missing.length}):</h4>`;
      missing.forEach(m => {
        html += `
          <div class="finding-issue-card severity-medium">
            <div class="finding-title-row">
              <span class="finding-title">${escapeHtml(m.header)}</span>
              <span class="severity-badge badge-medium">Ausente</span>
            </div>
            <p class="finding-detail-text">${escapeHtml(m.purpose)}</p>
          </div>
        `;
      });
    }

    elements.visualResultsFeed.innerHTML = html;
  }

  // 4. TLS Certificate Visual
  function renderTlsVisual(data) {
    const valid = data.certificate_valid;
    let html = `
      <div class="visual-summary-banner" style="border-color: ${valid ? 'var(--emerald-success)' : 'var(--rose-danger)'};">
        <div>
          <div class="summary-headline">Certificado TLS: ${escapeHtml(data.hostname || '')}</div>
          <div class="summary-detail">Emissor: ${escapeHtml(data.issuer || '')} | Protocolo: ${escapeHtml(data.tls_version || '')}</div>
        </div>
        <div class="summary-count-badge" style="color: ${valid ? 'var(--emerald-success)' : 'var(--rose-danger)'}; font-size: 15px;">
          ${valid ? 'VÁLIDO' : 'EXPIRADO'}
        </div>
      </div>
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 12px;">
        <div class="finding-issue-card severity-low">
          <div class="finding-title">Validade</div>
          <div class="finding-detail-text">Expira em: <strong>${escapeHtml(data.valid_until || '')}</strong> (${data.days_until_expiration || 0} dias restantes)</div>
        </div>
        <div class="finding-issue-card severity-low">
          <div class="finding-title">Cifra de Negociação</div>
          <div class="finding-detail-text">${escapeHtml(data.cipher_suite || 'N/A')}</div>
        </div>
      </div>
    `;
    elements.visualResultsFeed.innerHTML = html;
  }

  // 5. DNS Records & Email Hygiene Visual
  function renderDnsVisual(data) {
    const posture = data.email_security_posture || {};
    let html = `
      <div class="visual-summary-banner">
        <div>
          <div class="summary-headline">Postura de E-mail & DNS: ${escapeHtml(data.domain || '')}</div>
          <div class="summary-detail">Proteção contra spoofing e personificação de identidade.</div>
        </div>
      </div>
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 12px;">
        <div class="finding-issue-card ${posture.spf_configured ? 'severity-low' : 'severity-high'}">
          <div class="finding-title">Registro SPF</div>
          <div class="finding-detail-text">${escapeHtml(posture.spf_assessment || 'Não configurado')}</div>
        </div>
        <div class="finding-issue-card ${posture.dmarc_configured ? 'severity-low' : 'severity-high'}">
          <div class="finding-title">Política DMARC</div>
          <div class="finding-detail-text">${escapeHtml(posture.dmarc_assessment || 'Não configurado')}</div>
        </div>
      </div>
    `;
    elements.visualResultsFeed.innerHTML = html;
  }

  // 6. MITRE ATT&CK Visual
  function renderMitreVisual(data) {
    const results = data.results || [];
    let html = `
      <div class="visual-summary-banner">
        <div>
          <div class="summary-headline">Mapeamento MITRE ATT&CK Enterprise</div>
          <div class="summary-detail">${results.length} técnicas identificadas para a consulta.</div>
        </div>
        <div class="summary-count-badge">${results.length} TTPs</div>
      </div>
    `;
    results.forEach(t => {
      html += `
        <div class="finding-issue-card severity-low" style="margin-top: 10px;">
          <div class="finding-title-row">
            <span class="finding-title">${escapeHtml(t.technique_id)}: ${escapeHtml(t.name)}</span>
            <span class="severity-badge badge-low">${escapeHtml(t.tactic)}</span>
          </div>
          <p class="finding-detail-text">${escapeHtml(t.description)}</p>
          ${t.mitigation ? `<div class="finding-code-snip">Mitigação Defensiva: ${escapeHtml(t.mitigation)}</div>` : ''}
        </div>
      `;
    });
    elements.visualResultsFeed.innerHTML = html;
  }

  // 7. Dockerfile CIS Audit
  function renderDockerfileVisual(data) {
    const issues = data.issues || [];
    let html = `
      <div class="visual-summary-banner" style="border-color: ${issues.length > 0 ? 'var(--rose-danger)' : 'var(--emerald-success)'};">
        <div>
          <div class="summary-headline">Auditoria CIS Dockerfile</div>
          <div class="summary-detail">${issues.length} não-conformidades de segurança detectadas.</div>
        </div>
        <div class="summary-count-badge">${issues.length} Riscos</div>
      </div>
    `;
    issues.forEach(iss => {
      html += `
        <div class="finding-issue-card severity-high" style="margin-top: 8px;">
          <div class="finding-title-row">
            <span class="finding-title">${escapeHtml(iss.rule || 'CIS Benchmark')}</span>
            <span class="severity-badge badge-high">${escapeHtml(iss.severity || 'HIGH')}</span>
          </div>
          <p class="finding-detail-text">${escapeHtml(iss.description)}</p>
          ${iss.remediation ? `<div class="finding-code-snip">Remediação: ${escapeHtml(iss.remediation)}</div>` : ''}
        </div>
      `;
    });
    elements.visualResultsFeed.innerHTML = html;
  }

  // 8. IAM Policy Audit
  function renderIamPolicyVisual(data) {
    const risks = data.risks || [];
    let html = `
      <div class="visual-summary-banner" style="border-color: ${risks.length > 0 ? 'var(--rose-danger)' : 'var(--emerald-success)'};">
        <div>
          <div class="summary-headline">Auditoria de Políticas IAM de Nuvem</div>
          <div class="summary-detail">${risks.length} permissões excessivas ou riscos de escalonamento.</div>
        </div>
        <div class="summary-count-badge">${risks.length} Alertas</div>
      </div>
    `;
    risks.forEach(r => {
      html += `
        <div class="finding-issue-card severity-critical" style="margin-top: 8px;">
          <div class="finding-title-row">
            <span class="finding-title">${escapeHtml(r.type || 'IAM Privilege Risk')}</span>
            <span class="severity-badge badge-critical">CRITICAL</span>
          </div>
          <p class="finding-detail-text">${escapeHtml(r.description || '')}</p>
        </div>
      `;
    });
    elements.visualResultsFeed.innerHTML = html;
  }

  // 9. DFIR Incident Triage
  function renderIncidentTriageVisual(data) {
    const sev = data.severity || 'P3 - Medium';
    const playbook = data.immediate_containment_playbook || [];
    let html = `
      <div class="visual-summary-banner" style="border-color: var(--rose-danger);">
        <div>
          <div class="summary-headline">Triagem DFIR: ${escapeHtml(data.incident_id || 'INC-NOVO')}</div>
          <div class="summary-detail">Classificação NIST: <strong>${escapeHtml(sev)}</strong></div>
        </div>
        <div class="summary-count-badge" style="color: var(--rose-danger);">${escapeHtml(sev.split(' ')[0])}</div>
      </div>
      <h4 style="font-size: 13px; font-weight: 700; color: #fff; margin: 12px 0 8px 0;">Playbook de Contenção Imediata:</h4>
    `;
    playbook.forEach((item, idx) => {
      html += `
        <div class="finding-issue-card severity-medium" style="margin-top: 6px;">
          <div class="finding-title-row">
            <span class="finding-title">Passo ${idx + 1}: ${escapeHtml(item.action || item)}</span>
          </div>
        </div>
      `;
    });
    elements.visualResultsFeed.innerHTML = html;
  }

  // 10. SAST, Secrets & OWASP Findings
  function renderSastVisual(data, toolName) {
    const findings = data.findings || data.violations || [];
    let html = `
      <div class="visual-summary-banner">
        <div>
          <div class="summary-headline">Varredura de Código & Higiene: ${escapeHtml(toolName)}</div>
          <div class="summary-detail">${findings.length} achados reportados. Arquivos inspecionados: ${data.files_scanned || 'N/A'}.</div>
        </div>
        <div class="summary-count-badge">${findings.length} Achados</div>
      </div>
    `;
    findings.forEach(f => {
      const sev = (f.severity || 'medium').toLowerCase();
      html += `
        <div class="finding-issue-card severity-${sev}" style="margin-top: 8px;">
          <div class="finding-title-row">
            <span class="finding-title">${escapeHtml(f.title || f.rule || 'Vulnerabilidade')}</span>
            <span class="severity-badge badge-${sev}">${escapeHtml(f.severity || 'MEDIUM')}</span>
          </div>
          <p class="finding-detail-text">${escapeHtml(f.description || '')}</p>
          ${f.file ? `<div class="finding-code-snip">${escapeHtml(f.file)}${f.line ? `:${f.line}` : ''}</div>` : ''}
        </div>
      `;
    });
    elements.visualResultsFeed.innerHTML = html;
  }

  // Generic Visual Fallback
  function renderGenericVisual(data, tool) {
    if (typeof data !== 'object' || data === null) {
      elements.visualResultsFeed.innerHTML = `
        <div class="finding-issue-card severity-low">
          <p class="finding-detail-text">${escapeHtml(String(data))}</p>
        </div>
      `;
      return;
    }

    let html = `
      <div class="visual-summary-banner">
        <div class="summary-headline">Execução Concluída com Sucesso</div>
      </div>
      <div style="display: flex; flex-direction: column; gap: 8px; margin-top: 12px;">
    `;

    Object.keys(data).forEach(k => {
      const v = data[k];
      const valStr = typeof v === 'object' ? JSON.stringify(v) : String(v);
      html += `
        <div class="finding-issue-card severity-low">
          <div class="finding-title">${escapeHtml(k)}</div>
          <div class="finding-detail-text">${escapeHtml(valStr)}</div>
        </div>
      `;
    });

    html += `</div>`;
    elements.visualResultsFeed.innerHTML = html;
  }

  // Copy result to clipboard
  function copyResultToClipboard() {
    if (!state.lastExecutionResult) {
      showToast('Nenhum resultado para copiar.', 'error');
      return;
    }
    const text = JSON.stringify(state.lastExecutionResult.data, null, 2);
    navigator.clipboard.writeText(text);
    showToast('JSON copiado com sucesso!', 'success');
  }

  // --- TIMELINE CONTROLLER ---
  async function fetchTimeline() {
    try {
      const skill = elements.timelineSkillFilter.value;
      const url = `/api/memory/timeline?limit=60${skill ? `&skill=${encodeURIComponent(skill)}` : ''}`;
      const res = await fetch(url);
      const data = await res.json();
      renderTimelineEvents(data.timeline || []);
    } catch (err) {
      elements.timelineEventsFeed.innerHTML = `<div class="loading-placeholder">Erro ao carregar linha do tempo: ${err.message}</div>`;
    }
  }

  function renderTimelineEvents(events) {
    if (events.length === 0) {
      elements.timelineEventsFeed.innerHTML = `<div class="loading-placeholder">Nenhuma atividade registrada ainda nesta habilidade.</div>`;
      return;
    }

    let html = '';
    events.forEach(evt => {
      const skill = state.skills.find(s => s.id === evt.skill) || { icon: '🛡️', color: '#6366f1' };
      html += `
        <div class="timeline-event-card">
          <div class="event-icon-box" style="color: ${skill.color};">
            ${skill.icon}
          </div>
          <div class="event-content-box">
            <div class="event-header-row">
              <span class="event-tool-name">${escapeHtml(evt.tool_name)}</span>
              <span class="event-time-stamp">${escapeHtml(evt.timestamp)} (${evt.duration_ms}ms)</span>
            </div>
            <p class="event-summary-text">${escapeHtml(evt.summary)}</p>
          </div>
        </div>
      `;
    });

    elements.timelineEventsFeed.innerHTML = html;
  }

  // Save Finding to Memory
  async function handleSaveFinding(e) {
    e.preventDefault();
    const title = document.getElementById('finding-title').value.trim();
    const category = document.getElementById('finding-category').value;
    const skill = document.getElementById('finding-skill').value;
    const tags = document.getElementById('finding-tags').value.split(',').map(s => s.trim()).filter(Boolean);
    const content = document.getElementById('finding-content').value.trim();

    try {
      const res = await fetch('/api/memory/remember', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title, category, skill, tags, content }),
      });
      if (res.ok) {
        showToast('Descoberta salva na memória universal com sucesso!', 'success');
        elements.findingModalBackdrop.style.display = 'none';
        elements.newFindingForm.reset();
        if (state.currentView === 'timeline') fetchTimeline();
      }
    } catch (err) {
      showToast(`Erro ao salvar: ${err.message}`, 'error');
    }
  }

  // --- DOSSIER CONTROLLER ---
  async function fetchDossierReport() {
    try {
      elements.dossierContentPre.textContent = 'Gerando dossiê de investigação a partir da base SQLite...';
      const res = await fetch('/api/memory/report');
      const text = await res.text();
      elements.dossierContentPre.textContent = text;
    } catch (err) {
      elements.dossierContentPre.textContent = `Erro ao gerar dossiê: ${err.message}`;
    }
  }

  // --- STEALTH MODE & ONION NODE CONTROLLER ---
  async function fetchStealthStatus() {
    try {
      const res = await fetch('/api/stealth/status');
      if (res.ok) {
        const cfg = await res.json();
        state.stealthConfig = cfg;
        updateStealthUI(cfg);
      }
    } catch (err) {
      console.warn('Erro ao consultar status stealth:', err);
    }
  }

  function updateStealthUI(cfg) {
    if (!cfg) return;
    const isEnabled = Boolean(cfg.enabled);

    // Header badge & button pill
    if (elements.stealthStatusBadge) {
      if (isEnabled) {
        elements.stealthStatusBadge.textContent = 'ATIVO';
        elements.stealthStatusBadge.className = 'stealth-badge-status active';
        if (elements.btnStealthModal) elements.btnStealthModal.classList.add('active');
      } else {
        elements.stealthStatusBadge.textContent = 'OFF';
        elements.stealthStatusBadge.className = 'stealth-badge-status off';
        if (elements.btnStealthModal) elements.btnStealthModal.classList.remove('active');
      }
    }

    // Modal state cards
    if (elements.stealthIndicatorDot) {
      elements.stealthIndicatorDot.className = isEnabled 
        ? 'stealth-pulse-indicator status-on' 
        : 'stealth-pulse-indicator status-off';
    }

    if (elements.stealthStatusCard) {
      if (isEnabled) {
        elements.stealthStatusCard.classList.add('status-active');
      } else {
        elements.stealthStatusCard.classList.remove('status-active');
      }
    }

    if (elements.stealthCardTitle) {
      elements.stealthCardTitle.textContent = isEnabled 
        ? 'Modo Stealth ATIVO (Tráfego Camuflado)' 
        : 'Modo Stealth Desativado';
    }

    if (elements.stealthCardDesc) {
      elements.stealthCardDesc.textContent = isEnabled
        ? `Tráfego de rede e OSINT roteados via ${cfg.proxy_url || 'socks5://127.0.0.1:9050'}`
        : 'Conexões são realizadas diretamente com seu endereço IP real de operadora.';
    }

    // Inputs
    if (elements.stealthToggleInput) {
      elements.stealthToggleInput.checked = isEnabled;
    }
    if (elements.stealthProxyUrl && cfg.proxy_url) {
      elements.stealthProxyUrl.value = cfg.proxy_url;
    }
    if (elements.stealthDnsInput) {
      elements.stealthDnsInput.checked = cfg.dns_over_tor !== false;
    }

    // Exit IP details if tested
    if (cfg.last_exit_ip && elements.stealthIpBanner) {
      elements.stealthIpBanner.classList.remove('hidden');
      if (elements.stealthExitIp) elements.stealthExitIp.textContent = cfg.last_exit_ip;
      if (elements.stealthTorVerified) {
        elements.stealthTorVerified.textContent = cfg.is_tor ? 'Confirmado (Rede Tor)' : 'Proxy Ativo';
        elements.stealthTorVerified.style.color = cfg.is_tor ? '#34d399' : '#fbbf24';
      }
    }
  }

  function openStealthModal() {
    if (state.stealthConfig) {
      updateStealthUI(state.stealthConfig);
    } else {
      fetchStealthStatus();
    }
    if (elements.stealthModal) {
      elements.stealthModal.style.display = 'flex';
    }
  }

  function closeStealthModal() {
    if (elements.stealthModal) {
      elements.stealthModal.style.display = 'none';
    }
  }

  async function handleSaveStealth(e) {
    e.preventDefault();
    const enabled = elements.stealthToggleInput ? elements.stealthToggleInput.checked : true;
    const proxy_url = elements.stealthProxyUrl ? elements.stealthProxyUrl.value.trim() : 'socks5://127.0.0.1:9050';
    const dns_over_tor = elements.stealthDnsInput ? elements.stealthDnsInput.checked : true;

    try {
      const res = await fetch('/api/stealth/configure', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled, proxy_url, dns_over_tor }),
      });
      const data = await res.json();
      if (res.ok) {
        state.stealthConfig = {
          ...state.stealthConfig,
          enabled,
          proxy_url,
          dns_over_tor,
        };
        updateStealthUI(state.stealthConfig);
        showToast(data.message || (enabled ? 'Modo Stealth ativado com sucesso!' : 'Modo Stealth desativado.'), 'success');
        closeStealthModal();
      } else {
        showToast(`Erro ao salvar: ${data.error || 'Falha na requisição'}`, 'error');
      }
    } catch (err) {
      showToast(`Erro ao conectar com API: ${err.message}`, 'error');
    }
  }

  async function handleTestTor() {
    if (!elements.btnTestTor) return;
    const originalText = elements.btnTestTor.innerHTML;
    elements.btnTestTor.disabled = true;
    elements.btnTestTor.innerHTML = '<span class="btn-icon">⏳</span> Testando...';

    const proxy_url = elements.stealthProxyUrl ? elements.stealthProxyUrl.value.trim() : 'socks5://127.0.0.1:9050';

    try {
      const res = await fetch('/api/stealth/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ proxy_url, timeout: 6.0 }),
      });
      const data = await res.json();

      if (data.connected) {
        showToast(data.message || 'Nó Tor conectado com sucesso!', 'success');
        if (elements.stealthIpBanner) elements.stealthIpBanner.classList.remove('hidden');
        if (elements.stealthExitIp) elements.stealthExitIp.textContent = data.exit_ip || 'IP Oculto';
        if (elements.stealthTorVerified) {
          elements.stealthTorVerified.textContent = data.is_tor ? 'Confirmado (Rede Tor)' : 'Proxy Detectado';
          elements.stealthTorVerified.style.color = '#34d399';
        }
        if (elements.stealthIndicatorDot) {
          elements.stealthIndicatorDot.className = 'stealth-pulse-indicator status-on';
        }
      } else {
        showToast(data.message || 'Não foi possível conectar ao nó Tor.', 'error');
        if (elements.stealthIndicatorDot) {
          elements.stealthIndicatorDot.className = 'stealth-pulse-indicator status-warn';
        }
      }
    } catch (err) {
      showToast(`Falha no teste: ${err.message}`, 'error');
    } finally {
      elements.btnTestTor.disabled = false;
      elements.btnTestTor.innerHTML = originalText;
    }
  }

  // Toast Notifications
  function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    elements.toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(-10px)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 3200);
  }

  // Boot
  document.addEventListener('DOMContentLoaded', init);
})();
