// @ts-check
/* ============================================================
   password-generator.js — shared "Generate password" dialog

   Any button carrying `data-password-generator` opens one shared
   `<dialog>` (injected once). The dialog shows a generated password,
   lets the admin tweak length + character sets, and fills the inputs
   named in `data-password-targets` (comma-separated element ids) on
   "Use password".

       <button type="button" class="btn btn--ghost btn--icon"
               data-password-generator
               data-password-targets="password,password2">…</button>

   Generation is server-side (`Actions.AdminsGeneratePassword` →
   `Sbpp\Security\PasswordGenerator`), so the charsets and the
   owner-configured defaults (`config.password.generator.*`, Settings
   > Main) have one source of truth. The first call of a page load
   sends no options and paints the defaults the server echoes back;
   later calls send the dialog's current options, so a tweak carries
   over to the next field on the same page.

   Disabled targets are skipped. Filled targets get bubbling `input`
   + `change` events so page-tail validators see the new value.

   Loaded globally from core/footer.tpl; a no-op on pages without a
   trigger.
   ============================================================ */
(function () {
    'use strict';

    var DIALOG_ID = 'password-generator-dialog';
    var FLAGS = ['lowercase', 'uppercase', 'digits', 'symbols', 'exclude_ambiguous'];
    var SETS = ['lowercase', 'uppercase', 'digits', 'symbols'];

    /** @returns {{call: (a:string,p?:object)=>Promise<any>}|null} */
    function api()     { return /** @type {any} */ (window.sb && /** @type {any} */ (window.sb).api) || null; }
    /** @returns {Record<string,string>|null} */
    function actions() { return /** @type {any} */ (window).Actions || null; }
    /**
     * @param {Element|null} btn
     * @param {boolean} busy
     */
    function setBusy(btn, busy) {
        if (!btn) return;
        var S = /** @type {any} */ (window).SBPP;
        if (S && typeof S.setBusy === 'function') S.setBusy(btn, busy);
        else /** @type {HTMLButtonElement} */ (btn).disabled = busy;
    }

    /** @type {string[]} */
    var targets = [];
    var loaded = false;
    var seq = 0;
    /** @type {number|undefined} */
    var debounce;

    /**
     * @param {HTMLElement} root
     * @param {string} id
     * @returns {HTMLInputElement}
     */
    function field(root, id) {
        return /** @type {HTMLInputElement} */ (root.querySelector('[data-pwgen="' + id + '"]'));
    }

    /** @returns {HTMLDialogElement} */
    function ensureDialog() {
        var existing = /** @type {HTMLDialogElement|null} */ (document.getElementById(DIALOG_ID));
        if (existing) return existing;

        /**
         * @param {string} key
         * @param {string} label
         */
        function checkbox(key, label) {
            return '<label class="flex items-center gap-2">'
                + '<input type="checkbox" data-pwgen="' + key + '" data-testid="password-generator-' + key.replace('_', '-') + '">'
                + '<span class="text-sm">' + label + '</span>'
                + '</label>';
        }

        var d = document.createElement('dialog');
        d.id = DIALOG_ID;
        d.className = 'palette';
        d.setAttribute('aria-labelledby', DIALOG_ID + '-title');
        d.setAttribute('data-testid', 'password-generator-dialog');
        d.setAttribute('hidden', '');
        d.setAttribute('style', 'max-width:32rem;width:90vw;padding:1.25rem;border-radius:0.75rem;border:1px solid var(--border)');
        d.innerHTML =
            '<form method="dialog" data-testid="password-generator-form">'
            + '<h2 id="' + DIALOG_ID + '-title" style="font-size:var(--fs-lg);font-weight:600;margin:0 0 0.75rem">Generate password</h2>'
            + '<div class="flex gap-2">'
            + '<input class="input font-mono" type="text" readonly spellcheck="false" autocomplete="off"'
            + ' aria-label="Generated password" data-pwgen="output" data-testid="password-generator-output" style="flex:1;min-width:0">'
            + '<button type="button" class="btn btn--ghost btn--icon" title="Copy" aria-label="Copy password"'
            + ' data-copy="" data-pwgen="copy" data-testid="password-generator-copy">'
            + '<i data-lucide="copy" style="width:14px;height:14px"></i></button>'
            + '<button type="button" class="btn btn--ghost btn--icon" title="Generate another" aria-label="Generate another"'
            + ' data-pwgen="regenerate" data-testid="password-generator-regenerate">'
            + '<i data-lucide="refresh-cw" style="width:14px;height:14px"></i></button>'
            + '</div>'
            + '<div class="mt-4">'
            + '<label class="label" for="' + DIALOG_ID + '-length">Length</label>'
            + '<div class="flex items-center gap-2">'
            + '<input type="range" id="' + DIALOG_ID + '-length" data-pwgen="length-range" data-testid="password-generator-length-range" style="flex:1;accent-color:var(--accent)">'
            + '<input class="input" type="number" aria-label="Length" data-pwgen="length" data-testid="password-generator-length" style="width:5rem">'
            + '</div>'
            + '</div>'
            + '<fieldset class="mt-4" style="border:0;padding:0;margin-inline:0">'
            + '<legend class="label">Characters</legend>'
            + '<div class="flex gap-4" style="flex-wrap:wrap">'
            + checkbox('lowercase', 'a-z')
            + checkbox('uppercase', 'A-Z')
            + checkbox('digits', '0-9')
            + checkbox('symbols', 'Symbols')
            + checkbox('exclude_ambiguous', 'Skip look-alikes')
            + '</div>'
            + '</fieldset>'
            + '<p class="text-xs mt-2" role="alert" data-pwgen="error" data-testid="password-generator-error" style="color:var(--danger);margin-bottom:0" hidden></p>'
            + '<div class="flex gap-2 mt-4" style="justify-content:flex-end">'
            + '<button type="button" class="btn btn--secondary" data-pwgen="cancel" data-testid="password-generator-cancel">Cancel</button>'
            + '<button type="submit" class="btn btn--primary" data-pwgen="use" data-testid="password-generator-use">'
            + '<i data-lucide="check" style="width:13px;height:13px"></i> Use password'
            + '</button>'
            + '</div>'
            + '</form>';
        document.body.appendChild(d);
        wireDialog(d);
        var lucide = /** @type {any} */ (window).lucide;
        if (lucide && typeof lucide.createIcons === 'function') lucide.createIcons();
        return d;
    }

    /**
     * @param {HTMLElement} d
     * @param {string} message
     */
    function showError(d, message) {
        var err = field(d, 'error');
        err.textContent = message;
        err.hidden = message === '';
    }

    /**
     * @param {HTMLElement} d
     * @returns {Record<string, number|boolean>}
     */
    function readOptions(d) {
        /** @type {Record<string, number|boolean>} */
        var opts = { length: parseInt(field(d, 'length').value, 10) || 0 };
        FLAGS.forEach(function (k) { opts[k] = field(d, k).checked; });
        return opts;
    }

    /**
     * @param {HTMLElement} d
     * @param {any} data
     */
    function paint(d, data) {
        var opts = data.options || {};
        var range = field(d, 'length-range');
        var num = field(d, 'length');
        [range, num].forEach(function (el) {
            el.min = String(data.min_length);
            el.max = String(data.max_length);
            el.value = String(opts.length);
        });
        FLAGS.forEach(function (k) { field(d, k).checked = !!opts[k]; });
        field(d, 'output').value = String(data.password || '');
        field(d, 'copy').setAttribute('data-copy', String(data.password || ''));
    }

    /**
     * @param {HTMLElement} d
     */
    function generate(d) {
        var a = api(), A = actions();
        var use = /** @type {HTMLButtonElement} */ (field(d, 'use'));
        var regen = field(d, 'regenerate');
        if (!a || !A) {
            showError(d, 'The API client is unavailable. Reload the page and try again.');
            use.disabled = true;
            return;
        }

        var params = {};
        if (loaded) {
            params = readOptions(d);
            var anySet = SETS.some(function (k) { return !!(/** @type {any} */ (params)[k]); });
            if (!anySet) {
                showError(d, 'Pick at least one character set.');
                use.disabled = true;
                return;
            }
        }

        var mine = ++seq;
        use.disabled = true;
        setBusy(regen, true);
        a.call(A.AdminsGeneratePassword, params).then(function (r) {
            if (mine !== seq) return;
            setBusy(regen, false);
            if (!r || r.ok === false || !r.data || !r.data.password) {
                showError(d, (r && r.error && r.error.message) || 'Could not generate a password.');
                return;
            }
            loaded = true;
            showError(d, '');
            paint(d, r.data);
            use.disabled = false;
        }).catch(function (err) {
            if (mine !== seq) return;
            setBusy(regen, false);
            showError(d, String(err && err.message ? err.message : err));
        });
    }

    /**
     * @param {HTMLElement} d
     * @param {number} delay
     */
    function scheduleGenerate(d, delay) {
        window.clearTimeout(debounce);
        debounce = window.setTimeout(function () { generate(d); }, delay);
    }

    /**
     * @param {HTMLDialogElement} d
     */
    function close(d) {
        window.clearTimeout(debounce);
        try { d.close(); } catch (_e) { /* not opened modally */ }
        d.setAttribute('hidden', '');
    }

    function fillTargets() {
        var d = /** @type {HTMLDialogElement} */ (document.getElementById(DIALOG_ID));
        var value = field(d, 'output').value;
        if (value === '') return;
        targets.forEach(function (id) {
            var el = /** @type {HTMLInputElement|null} */ (document.getElementById(id));
            if (!el || el.disabled) return;
            el.value = value;
            el.dispatchEvent(new Event('input', { bubbles: true }));
            el.dispatchEvent(new Event('change', { bubbles: true }));
        });
    }

    /**
     * @param {HTMLDialogElement} d
     */
    function wireDialog(d) {
        var range = field(d, 'length-range');
        var num = field(d, 'length');

        range.addEventListener('input', function () {
            num.value = range.value;
            scheduleGenerate(d, 150);
        });
        num.addEventListener('change', function () {
            var min = parseInt(num.min, 10), max = parseInt(num.max, 10);
            var n = parseInt(num.value, 10);
            if (isNaN(n)) n = min;
            n = Math.max(min, Math.min(max, n));
            num.value = String(n);
            range.value = String(n);
            scheduleGenerate(d, 0);
        });
        FLAGS.forEach(function (k) {
            field(d, k).addEventListener('change', function () { scheduleGenerate(d, 0); });
        });
        field(d, 'regenerate').addEventListener('click', function () { generate(d); });
        field(d, 'cancel').addEventListener('click', function () { close(d); });
        d.addEventListener('cancel', function () { d.setAttribute('hidden', ''); });

        var form = /** @type {HTMLFormElement} */ (d.querySelector('form'));
        form.addEventListener('submit', function (e) {
            e.preventDefault();
            if (/** @type {HTMLButtonElement} */ (field(d, 'use')).disabled) return;
            fillTargets();
            close(d);
        });
    }

    /**
     * @param {HTMLElement} trigger
     */
    function open(trigger) {
        targets = (trigger.getAttribute('data-password-targets') || '')
            .split(',')
            .map(function (s) { return s.trim(); })
            .filter(function (s) { return s !== ''; });

        var d = ensureDialog();
        showError(d, '');
        d.removeAttribute('hidden');
        try { d.showModal(); }
        catch (_e) { d.setAttribute('open', ''); }
        generate(d);
        try { field(d, 'output').focus(); } catch (_e) { /* focus may throw */ }
    }

    document.addEventListener('click', function (e) {
        var t = /** @type {Element|null} */ (e.target);
        if (!t || !t.closest) return;
        var trigger = /** @type {HTMLElement|null} */ (t.closest('[data-password-generator]'));
        if (!trigger || /** @type {HTMLButtonElement} */ (trigger).disabled) return;
        e.preventDefault();
        open(trigger);
    });
})();
