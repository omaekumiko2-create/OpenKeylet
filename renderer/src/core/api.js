/* Single Tauri IPC & event facade for the OpenKeylet desktop renderer. */
import { store } from './store.js';

export function invoke(command, args) {
  return window.__TAURI__.core.invoke(command, args);
}

export function listen(event, handler) {
  return window.__TAURI__?.event?.listen?.(event, handler);
}

let settingsWriteQueue = Promise.resolve();

export function updateSettings(patch) {
  const operation = settingsWriteQueue.then(() => invoke('update_settings', { patch }));
  settingsWriteQueue = operation.catch(() => {});
  return operation;
}

export const api = {
  state: () => invoke('get_state'),
  ownerStatus: () => invoke('owner_status'),
  ownerTouch: () => invoke('owner_touch'),
  ownerSetPin: (pin) => invoke('owner_set_pin', { pin }),
  ownerDisablePin: () => invoke('owner_disable_pin'),
  ownerUnlock: (pin) => invoke('owner_unlock', { pin }),
  ownerLock: () => invoke('owner_lock'),
  ownerSecrets: (id) => invoke('owner_secret_view', { id }),
  drafts: () => invoke('owner_editor_drafts'),
  saveDraft: (draftId, input) => invoke('save_editor_draft', { draftId, input }),
  deleteDraft: (id) => invoke('delete_editor_draft', { id }),
  copyOwnerValue: (value, sensitive = true) => invoke('copy_owner_value', { value, sensitive }),
  save: (input) => invoke('save_connection', { input, expectedUpdatedAt: store.editorExistingItem?.updatedAt || null }),
  setEnabled: (id, enabled) => invoke('set_connection_enabled', { id, enabled }),
  reorder: (ids, expectedOrder) => invoke('reorder_connections', { ids, expectedOrder }),
  remove: (id, expectedUpdatedAt) => invoke('delete_connection', { id, expectedUpdatedAt }),
  trash: () => invoke('owner_trash'),
  restore: (id, deletedAt) => invoke('owner_restore_item', { id, deletedAt }),
  purge: (id, deletedAt) => invoke('owner_purge_item', { id, deletedAt }),
  history: (id) => invoke('owner_password_history', { id }),
  clearHistory: (id, expectedUpdatedAt) => invoke('owner_clear_password_history', { id, expectedUpdatedAt }),
  addAgentNote: (id, text) => invoke('owner_add_agent_note', { id, text }),
  updateAgentNote: (id, noteId, text) => invoke('owner_update_agent_note', { id, noteId, text }),
  deleteAgentNote: (id, noteId) => invoke('owner_delete_agent_note', { id, noteId }),
  clearAgentNotes: (id) => invoke('owner_clear_agent_notes', { id }),
  setAgentNotesLocked: (id, locked) => invoke('owner_set_agent_notes_locked', { id, locked }),
  test: (id) => invoke('test_connection', { id }),
  settings: updateSettings,
  systemIntegration: () => invoke('system_integration_status'),
  setDesktopShortcut: (enabled) => invoke('set_desktop_shortcut', { enabled }),
  setLaunchAtLogin: (enabled) => invoke('set_launch_at_login', { enabled }),
  deleteActivity: (id) => invoke('delete_activity', { id }),
  deleteActivities: (ids) => invoke('delete_activities', { ids }),
  clear: () => invoke('clear_activities'),
  copyConfig: (format) => invoke('copy_mcp_config', { format }),
  agents: () => invoke('agent_mcp_status'),
  registerAgents: (clientIds) => invoke('agent_mcp_register', { clientIds }),
  repairAgent: (clientId) => invoke('agent_mcp_repair', { clientId }),
  removeAgent: (clientId) => invoke('agent_mcp_remove', { clientId }),
  chooseKey: () => invoke('choose_private_key'),
  chromeProfiles: () => invoke('list_chrome_profiles'),
  quickPair: (port) => invoke('quick_pair_browser', { port }),
  openChrome: (profileDirectory = null) => invoke('open_chrome_browser', profileDirectory ? { profileDirectory } : {}),
  testBrowserBridge: () => invoke('test_browser_bridge'),
  reloadBrowserExtension: () => invoke('reload_browser_extension'),
  resetPair: () => invoke('reset_browser_pairing'),
  extensionFolder: () => invoke('open_browser_extension_folder'),
  exportBackup: (password) => invoke('export_backup', { password }),
  pickBackupImportFile: () => invoke('pick_backup_import_file'),
  inspectDroppedBackupBytes: (fileName, content) => invoke('inspect_dropped_backup_bytes', { fileName, content }),
  prepareBackupImport: (password) => invoke('prepare_backup_import', { password }),
  commitBackupImport: (id, selectedItemIndices = null, selectedTrashIndices = null) => invoke('commit_backup_import', {
    id,
    ...(Array.isArray(selectedItemIndices) ? { selectedItemIndices } : {}),
    ...(Array.isArray(selectedTrashIndices) ? { selectedTrashIndices } : {}),
  }),
  cancelBackupImport: () => invoke('cancel_backup_import'),
  prepareImport: (format) => invoke('prepare_import', { format }),
  prepareSshConfigImport: (useDefault) => invoke('prepare_ssh_config_import', { useDefault }),
  smartParseText: (text, filename = null, url = null) => invoke('smart_parse_text', { text, filename, url }),
  readOwnerClipboard: () => invoke('read_owner_clipboard'),
  clearClipboardIfMatches: (text) => invoke('clear_clipboard_if_matches', { text }),
  attachTotpToItem: (id, totp, expectedUpdatedAt) => invoke('attach_totp_to_item', { id, totp, expectedUpdatedAt }),
  commitImport: (id) => invoke('commit_import', { id }),
  cancelImport: () => invoke('cancel_import'),
  dataFolder: () => invoke('open_data_folder'),
  window: (action) => invoke('window_action', { action }),
  generatePassword: (options) => invoke('generate_password', { options }),
  copyTotpCode: (secret) => invoke('copy_totp_code', { secret }),
  dragBrowserExtension: () => invoke('drag_browser_extension'),
  syncAppearanceTheme: (payload) => invoke('sync_appearance_theme', payload),
  startVerticalResize: (direction) => invoke('start_vertical_resize', { direction }),
  setEdgeDockEnabled: (enabled) => invoke('set_edge_dock_enabled', { enabled }),
  edgeDockExpand: () => invoke('edge_dock_expand'),
  edgeDockHover: (entered) => invoke('edge_dock_hover', { entered }),
};
