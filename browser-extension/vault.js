/* Unified owner-only vault management (logins, passkeys, cards, identities, notes, ssh, api).
   Runs exclusively in the extension popup. */
const OpenKeyletVaultUI = (() => {
  const q = id => document.getElementById(id);
  const { t, icon } = OpenKeyletUI;

  const LOGIN_FIELD_KEYS = ["username", "password", "totp", "secureNote"];
  const CARD_FIELD_KEYS = ["cardholderName", "cardNumber", "cardBrand", "cardExpMonth", "cardExpYear", "cardSecurityCode"];
  const IDENTITY_FIELD_KEYS = [
    "identityTitle", "firstName", "middleName", "lastName", "company", "email", "phone",
    "address1", "address2", "address3", "city", "state", "postalCode", "country",
    "passportNumber", "licenseNumber", "nationalId",
  ];
  const PLAINTEXT_FIELDS = new Set([
    "username", "cardholderName", "cardBrand", "cardExpMonth", "cardExpYear",
    "identityTitle", "firstName", "middleName", "lastName", "company", "email", "phone",
    "address1", "address2", "address3", "city", "state", "postalCode", "country",
  ]);
  const STANDARD_BY_TYPE = {
    login: LOGIN_FIELD_KEYS,
    card: [...CARD_FIELD_KEYS, "secureNote"],
    identity: [...IDENTITY_FIELD_KEYS, "secureNote"],
    secureNote: ["secureNote"],
  };

  let snapshot = { items: [], trash: [] };
  let personalMap = new Map();
  let pageAvailable = false;
  let signature = "";
  let editing = null;
  let history = null;
  let busy = false;
  let sequence = 0;
  let confirmResolver = null;

  function typeLabel(itemType) {
    const key = `type.${itemType}`;
    const label = t(key);
    return label === key ? itemType : label;
  }

  function fieldLabel(name) {
    const key = `field.${name}`;
    const label = t(key);
    return label === key ? name : label;
  }

  function makeBtn(text, handler, cls = "button secondary xs") {
    const b = document.createElement("button");
    b.type = "button";
    b.className = cls;
    b.textContent = text;
    b.onclick = handler;
    return b;
  }

  function makeIconBtn(iconName, title, handler, extraCls = "") {
    const b = document.createElement("button");
    b.type = "button";
    b.className = `icon-btn ${extraCls}`.trim();
    b.title = title;
    b.setAttribute("aria-label", title);
    b.append(icon(iconName));
    b.onclick = handler;
    return b;
  }

  function notifySheetState() {
    if (typeof syncChromeVisibility === "function") syncChromeVisibility();
  }

  function closeEditor() {
    sequence++;
    editing = null;
    q("vault-editor").reset();
    q("vault-editor").hidden = true;
    q("vault-editor-fields").replaceChildren();
    q("vault-uri-rows").replaceChildren();
    q("vault-editor-passkeys").replaceChildren();
    notifySheetState();
  }

  function closeHistory() {
    sequence++;
    history = null;
    q("vault-history-rows").replaceChildren();
    q("vault-history").hidden = true;
    notifySheetState();
  }

  function answerConfirm(value) {
    const resolve = confirmResolver;
    confirmResolver = null;
    const dlg = q("vault-confirm");
    if (dlg.open) dlg.close();
    dlg.hidden = true;
    q("vault-confirm-message").textContent = "";
    resolve?.(value);
  }

  function ask(message) {
    answerConfirm(false);
    q("vault-confirm-message").textContent = message;
    const dlg = q("vault-confirm");
    dlg.hidden = false;
    dlg.showModal();
    q("vault-confirm-accept").focus();
    return new Promise(resolve => { confirmResolver = resolve; });
  }

  async function mutate(action, args) {
    busy = true;
    try {
      await call(action, args);
      showError(t("vault.updated"), "success");
      signature = "";
    } catch (error) {
      showError(error);
    } finally {
      busy = false;
      refresh();
    }
  }

  function apply(value, personal = [], hasPage = false) {
    pageAvailable = Boolean(hasPage);
    if (!value) {
      snapshot = { items: [], trash: [] };
      personalMap = new Map();
      signature = "";
      q("vault-all-items").replaceChildren();
      return;
    }
    const nextPersonalMap = new Map((personal || []).map(p => [p.id, p]));
    const next = JSON.stringify({ value, personal, pageAvailable });
    if (next === signature) return;
    signature = next;
    snapshot = value;
    personalMap = nextPersonalMap;

    const folderEl = q("vault-folder");
    const currentFolder = folderEl.value;
    const folders = [...new Set([...value.items, ...value.trash.map(v => v.item)].map(i => i.folder).filter(Boolean))].sort();
    folderEl.replaceChildren(new Option(t("vault.allFolders"), ""), ...folders.map(f => new Option(f, f)));
    folderEl.hidden = folders.length === 0;
    if (folders.includes(currentFolder)) folderEl.value = currentFolder;
    render();
  }

  function render() {
    const trash = q("vault-view").value === "trash";
    q("vault-new").disabled = trash;
    q("vault-new-kind").disabled = trash;

    const searchInput = q("vault-search");
    const term = searchInput.value.trim().toLocaleLowerCase();
    q("vault-search-well").classList.toggle("has-query", Boolean(term));

    const kind = q("vault-kind").value;
    const folder = q("vault-folder").hidden ? "" : q("vault-folder").value;
    const favOnly = q("vault-favorites").checked;
    const source = trash ? snapshot.trash : snapshot.items.map(item => ({ item }));

    const items = source.filter(({ item }) =>
      (!kind || (kind === "passkey" ? item.passkeys?.length : item.itemType === kind))
      && (!folder || item.folder === folder)
      && (!favOnly || item.favorite)
      && (!term || [item.name, item.folder, item.baseUrl, ...(item.loginUris || []).map(u => u.uri)]
        .join(" ").toLocaleLowerCase().includes(term)))
      .sort((a, b) => Number(b.item.favorite) - Number(a.item.favorite) || a.item.name.localeCompare(b.item.name));

    const container = q("vault-all-items");
    container.replaceChildren();

    if (!items.length) {
      const empty = document.createElement("div");
      empty.className = "entries-empty";
      empty.textContent = t(trash ? "vault.emptyTrash" : "vault.emptyActive");
      container.append(empty);
      return;
    }

    for (const entry of items) {
      const item = entry.item;
      const row = document.createElement("article");
      row.className = "vault-row";
      row.dataset.vaultId = item.id;
      row.dataset.itemType = item.itemType;

      const head = document.createElement("div");
      head.className = "vault-row-head";

      const icoWrap = document.createElement("span");
      icoWrap.className = "vault-row-icon";
      icoWrap.append(icon(item.itemType === "login" && item.passkeys?.length && !item.baseUrl ? "passkey" : item.itemType));

      const info = document.createElement("div");
      info.className = "vault-row-info";

      const titleRow = document.createElement("div");
      titleRow.className = "vault-row-title";
      const title = document.createElement("strong");
      title.textContent = item.name;
      titleRow.append(title);
      if (item.favorite) {
        titleRow.append(icon("star", "vault-fav-star"));
      }

      const personalMeta = personalMap.get(item.id);
      const subParts = [
        typeLabel(item.itemType),
        personalMeta?.subtitle || "",
        item.folder && item.folder !== personalMeta?.subtitle ? item.folder : "",
        !item.enabled ? t("vault.disabled") : "",
      ].filter(Boolean);
      const sub = document.createElement("small");
      sub.className = "vault-row-sub";
      sub.textContent = subParts.join(" · ");

      info.append(titleRow, sub);
      head.append(icoWrap, info);

      const actions = document.createElement("div");
      actions.className = "vault-row-actions";

      if (trash) {
        actions.append(
          makeBtn(t("vault.restore"), () => mutate("vault-restore", { id: item.id, deletedAt: entry.deletedAt }), "button secondary xs"),
          makeBtn(t("vault.purge"), async () => {
            if (await ask(t("vault.confirmPurge"))) {
              await mutate("vault-purge", { id: item.id, deletedAt: entry.deletedAt });
            }
          }, "button danger-soft xs"),
        );
      } else {
        if ((item.itemType === "card" || item.itemType === "identity") && item.enabled) {
          const fillBtn = makeBtn(t("vault.fill"), async () => {
            fillBtn.disabled = true;
            try {
              const result = await call("personal-fill", { id: item.id });
              showError(t("site.fieldsFilled", { count: result.filled }), "success");
            } catch (e) {
              showError(e);
            } finally {
              fillBtn.disabled = !pageAvailable;
            }
          }, "button primary xs");
          fillBtn.disabled = !pageAvailable;
          fillBtn.dataset.vaultFill = "";
          actions.append(fillBtn);
        }

        const editBtn = makeBtn(t("vault.edit"), () => openItem(item.id), "button secondary xs");
        editBtn.dataset.vaultEdit = "";
        actions.append(editBtn);

        if (item.passwordHistoryCount) {
          actions.append(makeBtn(t("vault.history"), () => openHistory(item.id), "button quiet xs"));
        }

        const trashBtn = makeBtn(t("vault.trash"), async () => {
          if (await ask(t("vault.confirmTrash"))) {
            await mutate("vault-trash", { id: item.id, expectedUpdatedAt: item.updatedAt });
          }
        }, "button quiet xs");
        trashBtn.dataset.vaultTrash = "";
        actions.append(trashBtn);
      }

      row.append(head, actions);
      container.append(row);
    }
  }

  function addUri(uri = "", matchType = "origin") {
    const row = document.createElement("div");
    row.className = "vault-uri-row";

    const input = document.createElement("input");
    input.className = "input mono-input";
    input.value = uri;
    input.maxLength = 8192;
    input.dataset.uri = "";
    input.placeholder = "https://example.com";
    input.setAttribute("aria-label", t("editor.websiteAria"));

    const select = document.createElement("select");
    select.className = "input compact-select";
    select.dataset.match = "";
    for (const key of ["origin", "domain", "host", "exact", "prefix", "regex", "never"]) {
      select.add(new Option(t(`match.${key}`), key));
    }
    select.value = matchType;

    const removeBtn = makeIconBtn("close", t("vault.cancel"), () => row.remove(), "danger-hover");
    row.append(input, select, removeBtn);
    q("vault-uri-rows").append(row);
  }

  function showEditor(item, fields = []) {
    closeEditor();
    closeHistory();
    if (typeof closeSave === "function") closeSave();
    if (typeof closeQuickStore === "function") closeQuickStore();

    editing = item;
    const label = typeLabel(item.itemType);
    q("vault-editor-title").textContent = item.id
      ? t("editor.editTitle", { type: label })
      : t("editor.newTitle", { type: label });
    q("vault-item-name").value = item.name || "";
    q("vault-item-folder").value = item.folder || "";
    q("vault-item-favorite").checked = Boolean(item.favorite);
    q("vault-item-enabled").checked = item.enabled !== false;

    const values = Object.fromEntries(fields.map(field => [field.name, field.value]));
    const standardKeys = STANDARD_BY_TYPE[item.itemType] || ["secureNote"];
    const existingKeys = (item.modules || []).filter(m => m.secret).map(m => m.kind === "customSecret" ? m.name : m.kind);
    const allKeys = [...new Set([...standardKeys, ...existingKeys])];

    const fieldsEl = q("vault-editor-fields");
    fieldsEl.replaceChildren();

    for (const name of allKeys) {
      const wrap = document.createElement("div");
      wrap.className = "vault-field";

      const labelEl = document.createElement("label");
      labelEl.className = "field-label";
      labelEl.textContent = fieldLabel(name);

      const isNote = name === "secureNote";
      const input = document.createElement(isNote ? "textarea" : "input");
      input.className = isNote ? "input textarea" : (PLAINTEXT_FIELDS.has(name) ? "input" : "input mono-input");
      input.dataset.vaultField = name;
      input.id = `vault-field-${fieldsEl.children.length}`;
      labelEl.htmlFor = input.id;
      input.autocomplete = "off";
      input.maxLength = isNote ? 1048576 : 16384;
      if (isNote) {
        input.rows = 4;
      } else {
        input.type = PLAINTEXT_FIELDS.has(name) ? "text" : "password";
      }
      input.value = values[name] || "";
      if (name === "privateKey") input.readOnly = true;

      const fieldRow = document.createElement("div");
      fieldRow.className = "vault-field-row";

      const btnGroup = document.createElement("div");
      btnGroup.className = "vault-field-btns";

      if (!isNote && input.type === "password") {
        let revealed = false;
        const eyeBtn = makeIconBtn("eye", t("save.show"), () => {
          revealed = !revealed;
          input.type = revealed ? "text" : "password";
          eyeBtn.replaceChildren(icon(revealed ? "eyeOff" : "eye"));
          eyeBtn.title = t(revealed ? "save.hide" : "save.show");
        });
        btnGroup.append(eyeBtn);
      }

      const copyBtn = makeIconBtn("copy", t("gen.copy"), async () => {
        try {
          await navigator.clipboard.writeText(input.value);
          showError(t("vault.copied"), "success");
        } catch (e) {
          showError(e);
        }
      });
      btnGroup.append(copyBtn);

      fieldRow.append(input, btnGroup);
      wrap.append(labelEl, fieldRow);
      fieldsEl.append(wrap);
    }

    q("vault-editor-websites").hidden = item.itemType !== "login";
    const uris = item.loginUris?.length ? item.loginUris : item.baseUrl ? [{ uri: item.baseUrl, matchType: "origin" }] : [];
    for (const rule of uris) addUri(rule.uri, rule.matchType);

    const passkeysEl = q("vault-editor-passkeys");
    passkeysEl.replaceChildren();
    for (const key of item.passkeys || []) {
      const chip = document.createElement("div");
      chip.className = "passkey-chip";
      chip.append(icon("passkey"));
      const txt = document.createElement("span");
      txt.textContent = `${key.rpId} · ${key.displayName || key.userName}`;
      chip.append(txt);
      passkeysEl.append(chip);
    }

    q("vault-editor").hidden = false;
    notifySheetState();
    q("vault-item-name").focus();
  }

  async function openItem(id) {
    const stamp = ++sequence;
    busy = true;
    try {
      const result = await call("vault-get", { id });
      if (stamp === sequence) showEditor(result.item, result.fields);
    } catch (e) {
      showError(e);
    } finally {
      busy = false;
    }
  }

  async function save(event) {
    event.preventDefault();
    if (!editing || busy) return;
    busy = true;
    try {
      const item = editing;
      const modules = (item.modules || []).map(m => ({ kind: m.kind, name: m.name, value: m.value, agentVisible: m.agentVisible }));
      const secrets = { namedSecrets: {} };
      const removeSecretNames = [];
      const standardSet = new Set(STANDARD_BY_TYPE[item.itemType] || ["secureNote"]);

      for (const input of q("vault-editor-fields").querySelectorAll("[data-vault-field]")) {
        const name = input.dataset.vaultField;
        if (name === "privateKey") continue;
        if (!modules.some(m => (m.kind === "customSecret" ? m.name : m.kind) === name)) {
          modules.push({ kind: standardSet.has(name) ? name : "customSecret", name, value: "", agentVisible: false });
        }
        if (!input.value) removeSecretNames.push(name);
        else if (name === "password") secrets.password = input.value;
        else if (name === "passphrase") secrets.passphrase = input.value;
        else secrets.namedSecrets[name] = input.value;
      }

      let loginUris = item.loginUris || [];
      if (item.itemType === "login") {
        loginUris = [...q("vault-uri-rows").children]
          .map(row => ({ uri: row.querySelector("[data-uri]").value.trim(), matchType: row.querySelector("[data-match]").value }))
          .filter(u => u.uri);
        const urlIndex = modules.findIndex(m => m.kind === "url");
        if (urlIndex >= 0) modules.splice(urlIndex, 1);
        const web = loginUris.find(u => /^https?:\/\//.test(u.uri));
        if (web) modules.push({ kind: "url", value: web.uri, agentVisible: false });
      }

      const input = {
        id: item.id || null,
        itemType: item.itemType,
        name: q("vault-item-name").value,
        folder: q("vault-item-folder").value,
        favorite: q("vault-item-favorite").checked,
        enabled: q("vault-item-enabled").checked,
        modules,
        secrets,
        removeSecretNames,
        loginUris,
        description: item.description || "",
        httpAuthType: item.httpAuthType || "",
        authHeader: item.authHeader || "",
        authLocation: item.authLocation || "",
        authPrefix: item.authPrefix || "",
        apiAuthHeaders: item.apiAuthHeaders || [],
        testPath: item.testPath || "",
      };
      await call("vault-save", { input, expectedUpdatedAt: item.updatedAt });
      closeEditor();
      signature = "";
      showError(t("save.saved"), "success");
    } catch (e) {
      showError(e);
    } finally {
      busy = false;
      refresh();
    }
  }

  async function openHistory(id) {
    closeEditor();
    closeHistory();
    const stamp = ++sequence;
    busy = true;
    try {
      const view = await call("vault-history", { id });
      if (stamp !== sequence) return;
      history = { id, updatedAt: view.updatedAt };
      const rowsEl = q("vault-history-rows");
      rowsEl.replaceChildren();

      for (const entry of view.entries) {
        const row = document.createElement("div");
        row.className = "history-row";

        const date = document.createElement("small");
        date.textContent = new Date(entry.changedAt).toLocaleString();

        const fieldRow = document.createElement("div");
        fieldRow.className = "vault-field-row";

        const input = document.createElement("input");
        input.className = "input mono-input";
        input.type = "password";
        input.readOnly = true;
        input.autocomplete = "off";
        input.value = entry.password;

        let revealed = false;
        const eyeBtn = makeIconBtn("eye", t("save.show"), () => {
          revealed = !revealed;
          input.type = revealed ? "text" : "password";
          eyeBtn.replaceChildren(icon(revealed ? "eyeOff" : "eye"));
          eyeBtn.title = t(revealed ? "save.hide" : "save.show");
        });
        const copyBtn = makeIconBtn("copy", t("gen.copy"), async () => {
          try {
            await navigator.clipboard.writeText(input.value);
            showError(t("vault.copied"), "success");
          } catch (e) {
            showError(e);
          }
        });

        const btns = document.createElement("div");
        btns.className = "vault-field-btns";
        btns.append(eyeBtn, copyBtn);

        fieldRow.append(input, btns);
        row.append(date, fieldRow);
        rowsEl.append(row);
      }

      if (!view.entries.length) {
        const empty = document.createElement("div");
        empty.className = "history-empty";
        empty.textContent = t("history.empty");
        rowsEl.append(empty);
      }

      q("vault-history-clear").hidden = !view.entries.length;
      q("vault-history").hidden = false;
      notifySheetState();
    } catch (e) {
      showError(e);
    } finally {
      busy = false;
    }
  }

  // Event bindings
  for (const id of ["vault-search", "vault-kind", "vault-folder", "vault-favorites", "vault-view"]) {
    q(id).addEventListener(id === "vault-search" ? "input" : "change", render);
  }
  q("vault-search-clear").addEventListener("click", () => {
    const input = q("vault-search");
    if (input.value) {
      input.value = "";
      render();
    }
    input.focus();
  });
  q("vault-new").onclick = () => showEditor({ itemType: q("vault-new-kind").value, modules: [], enabled: true });
  q("vault-editor").onsubmit = save;
  q("vault-editor-cancel").onclick = () => { closeEditor(); refresh(); };
  q("vault-editor-back").onclick = () => { closeEditor(); refresh(); };
  q("vault-uri-add").onclick = () => addUri();
  q("vault-history-close").onclick = () => { closeHistory(); refresh(); };
  q("vault-history-back").onclick = () => { closeHistory(); refresh(); };
  q("vault-confirm-accept").onclick = () => answerConfirm(true);
  q("vault-confirm-cancel").onclick = () => answerConfirm(false);
  q("vault-confirm").oncancel = event => { event.preventDefault(); answerConfirm(false); };
  q("vault-history-clear").onclick = async () => {
    const current = history;
    if (!current || !(await ask(t("vault.confirmClearHistory")))) return;
    await mutate("vault-clear-history", { id: current.id, expectedUpdatedAt: current.updatedAt });
    await openHistory(current.id);
  };

  OpenKeyletUI.onChange(() => {
    signature = "";
    const firstFolderOpt = q("vault-folder")?.options?.[0];
    if (firstFolderOpt && firstFolderOpt.value === "") {
      firstFolderOpt.textContent = t("vault.allFolders");
    }
    render();
  });

  return {
    apply,
    render,
    isEditing: () => Boolean(editing || history || busy || confirmResolver),
    close: () => {
      closeEditor();
      closeHistory();
      answerConfirm(false);
      apply(null);
    },
  };
})();
