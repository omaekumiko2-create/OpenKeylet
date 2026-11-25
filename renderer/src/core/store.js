/* Single centralized mutable UI state and cross-view coordination hooks. */

export const ACTIVITY_PAGE_SIZE = 50;

export const store = {
  // Vault & system state
  state: null,
  systemIntegrationState: { desktopShortcut: false, launchAtLogin: false },
  ownerLockState: { pinConfigured: false, unlocked: false, expiresInSeconds: 0 },
  ownerPinSetupRequested: false,

  // Language
  languagePreference: 'auto',
  language: 'en',

  // Navigation, search & filters
  activePage: 'connections',
  currentActivityFilter: 'all',
  pageSearch: { connections: '', import: '', activity: '', settings: '' },
  currentItemTypeFilter: 'all',
  vaultViewMode: (() => {
    try { return localStorage.getItem('openkeylet.vaultView') === 'grid' ? 'grid' : 'list'; } catch (_) { return 'list'; }
  })(),
  currentSettingsFilter: 'all',
  titleSearchOpen: false,
  creationMode: 'add',

  // Editor & drafts
  currentModules: [],
  editorDrafts: [],
  currentDraftId: '',
  removedSecretFields: new Set(),
  editorExistingItem: null,
  editorSourceInput: null,
  editorOpenedFromDraft: false,
  editorInitialSnapshot: '',
  editorReturnFocus: null,
  editorItemId: null,
  editorOpening: false,
  editorClosing: null,
  editorSmartClipboardSource: '',
  editorSmartTotpUri: '',
  editorCandidateOnSaved: null,
  pendingTotpQrModuleIndex: -1,
  editingAgentNoteId: null,
  agentNoteBusy: false,

  // Drag & switch state
  switchPointerDrag: null,
  switchSelectionPending: false,
  suppressSwitchClick: null,
  itemPointerDrag: null,
  itemOrderSaving: false,
  suppressItemClick: false,
  modulePointerDrag: null,
  suppressModuleClick: false,

  // Integrations
  agentClients: [],
  chromeProfiles: [],
  agentRestartRequired: false,
  renderedConnectionsSignature: '',

  // Health check state
  itemCheckStates: new Map(),
  checkAllRunning: false,
  checkAllRunId: 0,
  checkAllProgress: { done: 0, total: 0 },
  lastCheckAllOutcome: '',
  autoCheckTimer: null,

  // Activity log pagination
  activityVisibleCount: ACTIVITY_PAGE_SIZE,
  activityMatchCount: 0,
  activityLoadPending: false,
  expandedActivityErrors: new Set(),

  // Confirmation modal
  confirmationResolver: null,
  confirmationPreviousFocus: null,
  confirmationInertElements: [],

  // Secondary modals
  vaultManagement: null,
  vaultManagementSequence: 0,
  migrationId: null,
  migrationMode: 'migration',
  migrationSequence: 0,
  mvaultState: null,
  mvaultSequence: 0,
  generatorTarget: null,
  generatorSequence: 0,
  backupPasswordResolve: null,
  backupPasswordExport: false,

  // Feature controllers (wired by main.js)
  githubBackup: null,
  appUpdater: null,
  importHub: null,
};

/**
 * Late-bound cross-view callbacks populated by main.js during initialization,
 * keeping view modules decoupled and avoiding circular ES module init hazards.
 */
export const hooks = {};
