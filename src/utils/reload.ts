// Simple, dependency-free modal confirmation for reload actions
// Usage: const ok = await confirmReload({ title, message }); if (ok) window.location.reload();

export type ConfirmReloadOptions = {
  title?: string;
  message?: string;
  confirmText?: string;
  cancelText?: string;
};

export function confirmReload(
  options: ConfirmReloadOptions = {}
): Promise<boolean> {
  const {
    title = "Reload Required",
    message = "The application needs to reload to apply recent changes.",
    confirmText = "Reload",
    cancelText = "Cancel",
  } = options;

  return new Promise<boolean>((resolve) => {
    // Overlay
    const overlay = document.createElement("div");
    overlay.style.position = "fixed";
    overlay.style.inset = "0";
    overlay.style.background = "rgba(0,0,0,0.5)";
    overlay.style.display = "flex";
    overlay.style.alignItems = "center";
    overlay.style.justifyContent = "center";
    overlay.style.zIndex = "10000";

    // Dialog
    const dialog = document.createElement("div");
    dialog.style.background = "#0f172a"; // slate-900
    dialog.style.border = "1px solid #334155"; // slate-700
    dialog.style.color = "#e2e8f0"; // slate-200
    dialog.style.borderRadius = "12px";
    dialog.style.padding = "20px";
    dialog.style.width = "min(92vw, 420px)";
    dialog.style.boxShadow = "0 10px 25px rgba(0,0,0,0.35)";

    dialog.innerHTML = `
      <div style="display:flex; align-items:center; gap:10px; margin-bottom:10px;">
        <div style="width:10px; height:10px; background:#38bdf8; border-radius:50%;"></div>
        <h3 style="margin:0; font-size:16px; font-weight:600;">${title}</h3>
      </div>
      <p style="margin:0 0 16px; font-size:14px; color:#cbd5e1;">${message}</p>
      <div style="display:flex; justify-content:flex-end; gap:8px;">
        <button data-action="cancel" style="padding:8px 14px; font-size:13px; border-radius:8px; background:#0b1220; border:1px solid #334155; color:#cbd5e1; cursor:pointer;">
          ${cancelText}
        </button>
        <button data-action="confirm" style="padding:8px 14px; font-size:13px; border-radius:8px; background:#2563eb; border:1px solid #1d4ed8; color:white; cursor:pointer;">
          ${confirmText}
        </button>
      </div>
    `;

    overlay.appendChild(dialog);
    document.body.appendChild(overlay);

    const cleanup = (result: boolean) => {
      try {
        document.body.removeChild(overlay);
      } catch {}
      resolve(result);
    };

    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) cleanup(false);
    });

    dialog
      .querySelector('[data-action="cancel"]')
      ?.addEventListener("click", () => cleanup(false));
    dialog
      .querySelector('[data-action="confirm"]')
      ?.addEventListener("click", () => cleanup(true));
  });
}

export async function promptReload(options?: ConfirmReloadOptions) {
  const ok = await confirmReload(options);
  if (ok) window.location.reload();
}
