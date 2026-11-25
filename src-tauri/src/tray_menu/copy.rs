use super::*;

pub fn platform_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "windows"
    }
}

pub fn normalize_lang(raw: &str) -> &'static str {
    crate::platform::normalize_ui_lang(raw)
}

pub(super) fn detect_env_locale_opt() -> Option<&'static str> {
    for var in ["LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(value) = std::env::var(var) {
            let trimmed = value.trim();
            if !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("c") && trimmed != "POSIX" {
                let base = trimmed.split('.').next().unwrap_or(trimmed);
                return Some(normalize_lang(base));
            }
        }
    }
    None
}

#[derive(Debug, Clone, Copy)]
pub struct TrayCopy {
    pub tooltip_unlocked: &'static str,
    pub tooltip_locked: &'static str,
    pub status_unlocked: &'static str,
    pub status_locked: &'static str,
    pub items_suffix: &'static str,
    pub update_available: &'static str,
    pub show_window: &'static str,
    pub hide_window: &'static str,
    pub new_item: &'static str,
    pub smart_import: &'static str,
    pub generate_password: &'static str,
    pub browser_bridge: &'static str,
    pub bridge_connected: &'static str,
    pub bridge_listening: &'static str,
    pub settings: &'static str,
    pub lock_vault: &'static str,
    pub unlock_vault: &'static str,
    pub set_pin_lock: &'static str,
    pub quit: &'static str,
}

pub fn tray_copy(lang: &str) -> TrayCopy {
    match normalize_lang(lang) {
        "zh" => TrayCopy {
            tooltip_unlocked: "OpenKeylet — 本地加密密码库（已解锁）",
            tooltip_locked: "OpenKeylet — 本地加密密码库（已锁定）",
            status_unlocked: "已解锁",
            status_locked: "已锁定",
            items_suffix: "项凭据",
            update_available: "发现新版本",
            show_window: "显示 OpenKeylet",
            hide_window: "隐藏到托盘",
            new_item: "新建凭据",
            smart_import: "智能导入",
            generate_password: "生成并复制强密码",
            browser_bridge: "浏览器桥接",
            bridge_connected: "已连接",
            bridge_listening: "等待配对",
            settings: "系统设置",
            lock_vault: "立即锁定",
            unlock_vault: "解锁密码库",
            set_pin_lock: "设置 PIN 锁",
            quit: "退出 OpenKeylet",
        },
        "zh-TW" => TrayCopy {
            tooltip_unlocked: "OpenKeylet — 本機加密密碼庫（已解鎖）",
            tooltip_locked: "OpenKeylet — 本機加密密碼庫（已鎖定）",
            status_unlocked: "已解鎖",
            status_locked: "已鎖定",
            items_suffix: "項憑證",
            update_available: "發現新版本",
            show_window: "顯示 OpenKeylet",
            hide_window: "隱藏至系統匣",
            new_item: "新增憑證",
            smart_import: "智慧匯入",
            generate_password: "產生並複製強密碼",
            browser_bridge: "瀏覽器橋接",
            bridge_connected: "已連線",
            bridge_listening: "等待配對",
            settings: "系統設定",
            lock_vault: "立即鎖定",
            unlock_vault: "解鎖密碼庫",
            set_pin_lock: "設定 PIN 鎖",
            quit: "結束 OpenKeylet",
        },
        "ja" => TrayCopy {
            tooltip_unlocked: "OpenKeylet — ローカル暗号化ボールト（解除済み）",
            tooltip_locked: "OpenKeylet — ローカル暗号化ボールト（ロック中）",
            status_unlocked: "ロック解除",
            status_locked: "ロック中",
            items_suffix: "件",
            update_available: "アップデートあり",
            show_window: "OpenKeylet を表示",
            hide_window: "トレイに隠す",
            new_item: "新規項目",
            smart_import: "スマートインポート",
            generate_password: "強力なパスワードをコピー",
            browser_bridge: "ブラウザ連携",
            bridge_connected: "接続済み",
            bridge_listening: "待機中",
            settings: "システム設定",
            lock_vault: "今すぐロック",
            unlock_vault: "ロック解除",
            set_pin_lock: "PIN ロックを設定",
            quit: "OpenKeylet を終了",
        },
        "ko" => TrayCopy {
            tooltip_unlocked: "OpenKeylet — 로컬 암호화 금고 (잠금 해제됨)",
            tooltip_locked: "OpenKeylet — 로컬 암호화 금고 (잠김)",
            status_unlocked: "잠금 해제",
            status_locked: "잠김",
            items_suffix: "개 항목",
            update_available: "새 버전 있음",
            show_window: "OpenKeylet 표시",
            hide_window: "트레이로 숨기기",
            new_item: "새 항목",
            smart_import: "스마트 가져오기",
            generate_password: "강력한 비밀번호 복사",
            browser_bridge: "브라우저 브리지",
            bridge_connected: "연결됨",
            bridge_listening: "대기 중",
            settings: "시스템 설정",
            lock_vault: "지금 잠금",
            unlock_vault: "금고 잠금 해제",
            set_pin_lock: "PIN 잠금 설정",
            quit: "OpenKeylet 종료",
        },
        "es" => TrayCopy {
            tooltip_unlocked: "OpenKeylet — Bóveda local (Desbloqueada)",
            tooltip_locked: "OpenKeylet — Bóveda local (Bloqueada)",
            status_unlocked: "Desbloqueada",
            status_locked: "Bloqueada",
            items_suffix: "elementos",
            update_available: "Actualización disponible",
            show_window: "Mostrar OpenKeylet",
            hide_window: "Ocultar en bandeja",
            new_item: "Nuevo elemento",
            smart_import: "Importación inteligente",
            generate_password: "Copiar contraseña segura",
            browser_bridge: "Puente del navegador",
            bridge_connected: "Conectado",
            bridge_listening: "Esperando",
            settings: "Ajustes del sistema",
            lock_vault: "Bloquear ahora",
            unlock_vault: "Desbloquear bóveda",
            set_pin_lock: "Configurar PIN",
            quit: "Salir de OpenKeylet",
        },
        _ => TrayCopy {
            tooltip_unlocked: "OpenKeylet — Local Vault (Unlocked)",
            tooltip_locked: "OpenKeylet — Local Vault (Locked)",
            status_unlocked: "Unlocked",
            status_locked: "Locked",
            items_suffix: "items",
            update_available: "Update available",
            show_window: "Show OpenKeylet",
            hide_window: "Hide to tray",
            new_item: "New item",
            smart_import: "Smart import",
            generate_password: "Copy strong password",
            browser_bridge: "Browser bridge",
            bridge_connected: "Connected",
            bridge_listening: "Waiting",
            settings: "System settings",
            lock_vault: "Lock vault",
            unlock_vault: "Unlock vault",
            set_pin_lock: "Set PIN lock",
            quit: "Quit OpenKeylet",
        },
    }
}

pub fn format_tooltip(state: &TrayMenuState) -> String {
    let copy = tray_copy(&state.resolved_language);
    if state.unlocked {
        copy.tooltip_unlocked.to_owned()
    } else {
        copy.tooltip_locked.to_owned()
    }
}

pub fn theme_background_color(theme: &str) -> Color {
    if theme == "light" {
        Color(255, 255, 255, 255)
    } else {
        Color(11, 11, 13, 255)
    }
}
