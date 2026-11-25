/* Top HUD metrics strip across Vault, Import, Log, and System views. */
import { $, escapeHtml } from '../core/dom.js';
import { store } from '../core/store.js';
import { localized } from '../i18n/index.js';

function metricNumber(val, length = 4) {
  const exact = Math.max(0, Math.trunc(Number(val) || 0));
  const maximum = (10 ** length) - 1;
  const overflow = exact > maximum;
  const shown = String(Math.min(exact, maximum));
  return `<span class="seven-number ${overflow ? 'overflow' : ''}" role="img" aria-label="${exact}"><span class="metric-val" aria-hidden="true">${shown}</span>${overflow ? '<b class="seven-overflow" aria-hidden="true">+</b>' : ''}</span>`;
}

export function renderMetrics() {
  const state = store.state;
  const total = state.connections.length;
  const enabled = state.connections.filter((item) => item.enabled).length;
  const browserOn = ['listening', 'delegated'].includes(state.browserBridge.status);
  const mcpReady = state.mcp.status === 'ready';
  const now = Date.now();
  const since24Hours = now - 86_400_000;
  const activities24h = state.activities.filter((activity) => {
    const timestamp = new Date(activity.time).getTime();
    return Number.isFinite(timestamp) && timestamp >= since24Hours && timestamp <= now;
  });
  const errors24h = activities24h.filter((activity) => activity.status === 'error').length;
  const registeredAgents = store.agentClients.filter((client) => client.state === 'registered').length;
  const brokenAgents = store.agentClients.filter((client) => ['stale', 'conflict', 'error'].includes(client.state)).length;
  const importStats = store.importHub?.getStats?.() || { total: 0, selected: 0, ignored: 0 };

  const models = {
    connections: {
      value: total,
      mode: localized('密码库', 'VAULT'),
      unit: localized('项', 'ITEMS'),
      label: localized('密码库项目总数（点击查看全部项目）', 'Total vault items (click to show all)'),
      action: 'focus-connections-all',
      secondary: {
        value: enabled,
        mode: localized('已启用', 'ENABLED'),
        unit: total > 0 ? `/ ${total}` : localized('项', 'ITEMS'),
        tone: enabled > 0 ? 'active' : '',
        label: enabled > 0
          ? localized('点击定位到已启用的项目', 'Click to focus enabled vault items')
          : localized('已启用项目数，包含所有类型（点击查看）', 'Enabled items across all item types (click to view)'),
        action: 'focus-connections-enabled',
      },
    },
    import: {
      value: importStats.total,
      mode: localized('已识别', 'EXTRACTED'),
      unit: localized('项', 'FOUND'),
      label: localized('本地规则已提取的候选凭据数（点击查看全部候选）', 'Candidate credentials extracted locally (click to show all)'),
      action: 'focus-import-all',
      secondary: {
        value: importStats.selected,
        mode: localized('待入库', 'SELECTED'),
        unit: (importStats.selectable ?? importStats.total) > 0 ? `/ ${importStats.selectable ?? importStats.total}` : localized('项', 'READY'),
        tone: importStats.selected > 0 ? 'active' : '',
        label: importStats.selected > 0
          ? localized('点击定位到已勾选的待入库条目', 'Click to focus selected candidates ready to import')
          : localized('已勾选准备批量入库的条目数（点击查看）', 'Selected candidates ready to import (click to view)'),
        action: 'focus-import-selected',
      },
    },
    activity: {
      value: activities24h.length,
      mode: localized('近 24H 调用', 'CALLS · 24H'),
      unit: localized('次', ''),
      label: localized('本地日志中最近 24 小时的操作数（点击查看全部记录）', 'Operations in the local log from the last 24 hours (click to show all)'),
      action: 'focus-activity-all',
      secondary: {
        value: errors24h,
        mode: localized('异常失败', 'ERRORS · 24H'),
        unit: errors24h > 0 ? localized('项', '') : localized('正常', 'CLEAR'),
        tone: errors24h > 0 ? 'fault' : 'ok',
        label: errors24h > 0
          ? localized('点击筛选并定位到失败记录', 'Click to filter and focus failed activity items')
          : localized('本地日志中最近 24 小时的失败数（点击查看错误筛选）', 'Errors in the local log from the last 24 hours (click to view error filter)'),
        action: 'focus-activity-errors',
      },
    },
    settings: {
      value: registeredAgents,
      mode: localized('已接入 Agent', 'LINKED'),
      unit: localized('个', 'AGENTS'),
      label: localized('已注册 OpenKeylet MCP 的 Agent 客户端数（点击查看）', 'Agent clients registered with OpenKeylet MCP (click to focus)'),
      action: 'focus-linked-agents',
      secondary: {
        value: brokenAgents,
        mode: localized('待修复配置', 'REPAIR'),
        unit: brokenAgents > 0 ? localized('个', 'NEED FIX') : localized('健康', 'OK'),
        tone: brokenAgents > 0 ? 'warn' : 'ok',
        label: brokenAgents > 0
          ? localized('点击定位到待修复的 Agent 配置', 'Click to jump to the Agent configuration needing repair')
          : localized('需要修复接入配置的 Agent 客户端数（点击查看）', 'Agent clients whose connection configuration needs repair (click to view)'),
        action: 'focus-repair-agent',
      },
    },
  };

  const model = models[store.activePage] || models.connections;
  const secondary = model.secondary;
  const services = [
    {
      name: 'MCP',
      target: 'MCP',
      value: mcpReady ? 'READY' : state.mcp.status === 'error' ? 'ERROR' : 'SETUP',
      tone: mcpReady ? 'on' : state.mcp.status === 'error' ? 'fault' : 'warn',
      label: mcpReady
        ? localized('本地 MCP 就绪（点击查看设置）', 'Local MCP is ready (click to open setup)')
        : state.mcp.status === 'error'
          ? localized('本地 MCP 异常', 'Local MCP has an error')
          : localized('本地 MCP 需要配置', 'Local MCP needs setup'),
    },
    {
      name: 'WEB',
      target: 'WEB',
      value: state.browserBridge.status === 'error'
        ? 'ERROR'
        : !browserOn
          ? 'OFF'
          : !state.browserBridge.paired
            ? 'PAIR'
            : state.browserBridge.connected
              ? 'ON'
              : 'WAIT',
      tone: state.browserBridge.status === 'error'
        ? 'fault'
        : browserOn
          ? (state.browserBridge.paired && state.browserBridge.connected ? 'on' : 'warn')
          : '',
      label: state.browserBridge.status === 'error'
        ? localized('浏览器桥接异常', 'Browser Bridge has an error')
        : !browserOn
          ? localized('浏览器桥接已关闭（点击前往开启）', 'Browser Bridge is off (click to configure)')
          : !state.browserBridge.paired
            ? localized('浏览器扩展等待配对', 'Browser extension is waiting to pair')
            : state.browserBridge.connected
              ? localized('浏览器扩展已连接', 'Browser extension is connected')
              : localized('等待浏览器扩展连接', 'Waiting for the browser extension to connect'),
    },
    {
      name: 'PIN',
      target: 'APP',
      value: store.ownerLockState.pinConfigured ? 'ON' : 'OFF',
      tone: store.ownerLockState.pinConfigured ? 'on' : '',
      label: store.ownerLockState.pinConfigured
        ? localized('已开启本地 PIN 锁定', 'Local PIN protection is enabled')
        : localized('尚未设置本地 PIN（点击前往设置）', 'Local PIN protection is off (click to configure)'),
    },
  ];

  const primaryTag = model.action ? 'button' : 'div';
  const primaryAttrs = model.action
    ? `type="button" class="lcd-primary metric-cell metric-actionable" data-metric-action="${escapeHtml(model.action)}"`
    : 'class="lcd-primary metric-cell" role="group"';
  const secondaryTag = secondary.action ? 'button' : 'div';
  const secondaryAttrs = secondary.action
    ? `type="button" class="lcd-secondary metric-cell metric-actionable ${secondary.tone || ''}" data-metric-action="${escapeHtml(secondary.action)}"`
    : `class="lcd-secondary metric-cell ${secondary.tone || ''}" role="group"`;

  $('#metrics').innerHTML = `
    <div class="lcd-screen">
      <${primaryTag} ${primaryAttrs} aria-label="${escapeHtml(model.label)}" title="${escapeHtml(`${model.label}: ${model.value}`)}">
        <span class="metric-label" aria-hidden="true">${model.mode}</span>
        <div class="metric-readout">${metricNumber(model.value)}${model.unit ? `<span class="metric-unit" aria-hidden="true">${model.unit}</span>` : ''}</div>
      </${primaryTag}>
      <${secondaryTag} ${secondaryAttrs} aria-label="${escapeHtml(secondary.label)}" title="${escapeHtml(`${secondary.label}: ${secondary.value}`)}">
        <span class="metric-label" aria-hidden="true">${secondary.mode}</span>
        <div class="metric-readout">${metricNumber(secondary.value, 3)}${secondary.unit ? `<span class="metric-unit" aria-hidden="true">${secondary.unit}</span>` : ''}</div>
      </${secondaryTag}>
      <div class="lcd-system" role="group" aria-label="${localized('当前服务状态', 'Current service status')}">
        ${services.map((service) => `<button type="button" class="lcd-service ${service.tone}" data-metric-section="${service.target}" aria-label="${escapeHtml(service.label)}" title="${escapeHtml(service.label)}"><i class="lcd-dot ${service.tone}" aria-hidden="true"></i><span class="lcd-service-name" aria-hidden="true">${service.name}</span><strong class="lcd-status ${service.tone}" aria-hidden="true">${service.value}</strong></button>`).join('')}
      </div>
    </div>`;
}
