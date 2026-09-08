// @ts-check
/* ============================================================
   comment-actions.js — shared comment-action dispatcher

   Document-level delegates for:

     1. `data-action="comment-delete"` — confirm dialog +
        Actions.BansRemoveComment. Surfaces: public banlist /
        commslist inline threads, player-drawer comments, admin
        moderation queues (protests + submissions).
     2. `data-action="comment-compose"` — inline composer on the
        four queue cards (protests / submissions, current +
        archive). Banlist / commslist Add and Edit open the
        player drawer instead (`theme.js`).

   Delete: banlist / commslist (ctype B / C), including the player
   drawer, stay on the current page. theme.js removes the comment
   in place so scroll, pagination, and open disclosures survive.
   Protest / submission queue cards (S / P) still honour
   `message.redir` / reload after the toast settle.

   Each delete trigger carries:
     - `data-cid="<int>"`   — required (the comments row id)
     - `data-ctype="<B|C|S|P>"` — required
     - `data-page="<int>"`  — optional, defaults to -1

   Queue compose triggers carry `data-bid` + `data-ctype` and,
   for Edit, `data-cid` + `data-comment-text` (raw text, not the
   HTML body). Confirm chrome is a single shared `<dialog>`
   (injected once) — not `window.confirm()`.
   ============================================================ */
(function () {
    'use strict';

    /** @returns {{call: (a:string,p?:object)=>Promise<any>}|null} */
    function api()     { return /** @type {any} */ (window.sb && /** @type {any} */ (window.sb).api) || null; }
    /** @returns {Record<string,string>|null} */
    function actions() { return /** @type {any} */ (window).Actions || null; }
    /**
     * @param {Element|null} btn
     * @param {boolean} [busy]
     */
    function setBusy(btn, busy) {
        if (!btn) return;
        var S = /** @type {any} */ (window).SBPP;
        if (S && typeof S.setBusy === 'function') S.setBusy(btn, busy);
        else /** @type {HTMLButtonElement|HTMLAnchorElement} */ (btn).setAttribute('aria-busy', busy ? 'true' : 'false');
    }
    /**
     * @param {string} kind
     * @param {string} title
     * @param {string} [body]
     */
    function toast(kind, title, body) {
        var S = /** @type {any} */ (window).SBPP;
        if (S && typeof S.showToast === 'function') {
            S.showToast({ kind: kind, title: title, body: body || '' });
        }
    }

    /** @type {{cid: number, ctype: string, page: number, trigger: HTMLElement}|null} */
    var pending = null;

    /** @returns {HTMLDialogElement} */
    function ensureDialog() {
        var existing = /** @type {HTMLDialogElement|null} */ (document.getElementById('comment-delete-dialog'));
        if (existing) return existing;

        var d = document.createElement('dialog');
        d.id = 'comment-delete-dialog';
        d.className = 'palette';
        d.setAttribute('aria-labelledby', 'comment-delete-dialog-title');
        d.setAttribute('data-testid', 'comment-delete-dialog');
        d.setAttribute('hidden', '');
        d.setAttribute('style', 'max-width:32rem;width:90vw;padding:1.25rem;border-radius:0.75rem;border:1px solid var(--border)');
        d.innerHTML =
            '<form method="dialog" data-testid="comment-delete-form">'
            + '<h2 id="comment-delete-dialog-title" style="font-size:var(--fs-lg);font-weight:600;margin:0 0 0.25rem">Delete comment</h2>'
            + '<p class="text-sm text-muted m-0" style="margin-bottom:0.75rem">'
            + 'Delete this comment? This cannot be undone.'
            + '</p>'
            + '<div class="flex gap-2 mt-4" style="justify-content:flex-end">'
            + '<button type="button" class="btn btn--secondary" data-testid="comment-delete-cancel" value="cancel">Cancel</button>'
            + '<button type="submit" class="btn btn--danger" data-testid="comment-delete-submit" value="confirm">'
            + '<i data-lucide="trash-2" style="width:13px;height:13px"></i> Delete comment'
            + '</button>'
            + '</div>'
            + '</form>';
        document.body.appendChild(d);
        var lucide = /** @type {any} */ (window).lucide;
        if (lucide && typeof lucide.createIcons === 'function') lucide.createIcons();
        return d;
    }

    /**
     * @param {{cid: number, ctype: string, page: number, trigger: HTMLElement}} ctx
     */
    function openDeleteDialog(ctx) {
        pending = ctx;
        var d = ensureDialog();
        d.removeAttribute('hidden');
        try { d.showModal(); }
        catch (_e) { d.setAttribute('open', ''); }
        var submitBtn = /** @type {HTMLButtonElement|null} */ (d.querySelector('[data-testid="comment-delete-submit"]'));
        if (submitBtn) {
            try { submitBtn.focus(); } catch (_e) { /* focus may throw */ }
        }
    }

    function closeDeleteDialog() {
        var d = /** @type {HTMLDialogElement|null} */ (document.getElementById('comment-delete-dialog'));
        if (!d) return;
        try { d.close(); } catch (_e) { /* not opened modally */ }
        d.setAttribute('hidden', '');
        pending = null;
    }

    /**
     * @param {HTMLFormElement} form
     * @param {boolean} show
     */
    function showComposer(form, show) {
        form.hidden = !show;
        var card = form.closest('details');
        var addBtn = card && card.querySelector('[data-testid="queue-comment-add"]');
        if (addBtn instanceof HTMLElement) addBtn.hidden = show;
        if (!show) {
            var cidInput = /** @type {HTMLInputElement|null} */ (form.querySelector('input[name="cid"]'));
            var textarea = /** @type {HTMLTextAreaElement|null} */ (form.querySelector('textarea[name="ctext"]'));
            var err = /** @type {HTMLElement|null} */ (form.querySelector('[data-comment-error]'));
            if (cidInput) cidInput.value = '';
            if (textarea) textarea.value = '';
            if (err) err.hidden = true;
        }
    }

    /**
     * @param {HTMLElement} trigger
     */
    function openQueueComposer(trigger) {
        var card = trigger.closest('details');
        var form = card && /** @type {HTMLFormElement|null} */ (card.querySelector('[data-comment-composer]'));
        if (!form) {
            toast('error', 'Comment failed', 'Missing comment composer on this card.');
            return;
        }
        var cid = parseInt(trigger.getAttribute('data-cid') || '0', 10);
        var raw = trigger.getAttribute('data-comment-text') || '';
        var cidInput = /** @type {HTMLInputElement|null} */ (form.querySelector('input[name="cid"]'));
        var textarea = /** @type {HTMLTextAreaElement|null} */ (form.querySelector('textarea[name="ctext"]'));
        var err = /** @type {HTMLElement|null} */ (form.querySelector('[data-comment-error]'));
        showComposer(form, true);
        if (cidInput) cidInput.value = cid > 0 ? String(cid) : '';
        if (textarea) {
            textarea.value = cid > 0 ? raw : '';
            try { textarea.focus(); } catch (_e) { /* focus may throw */ }
        }
        if (err) err.hidden = true;
    }

    /**
     * @param {HTMLFormElement} form
     */
    function submitQueueComposer(form) {
        var a = api(), A = actions();
        var textarea = /** @type {HTMLTextAreaElement|null} */ (form.querySelector('textarea[name="ctext"]'));
        var cidInput = /** @type {HTMLInputElement|null} */ (form.querySelector('input[name="cid"]'));
        var err = /** @type {HTMLElement|null} */ (form.querySelector('[data-comment-error]'));
        var value = textarea ? textarea.value.trim() : '';
        if (value === '') {
            if (err) err.hidden = false;
            if (textarea) {
                try { textarea.focus(); } catch (_e) { /* focus may throw */ }
            }
            return;
        }
        if (err) err.hidden = true;
        if (!a || !A) {
            toast('error', 'Comment failed', 'The API client is unavailable. Reload the page and try again.');
            return;
        }
        var bid = parseInt(form.getAttribute('data-bid') || '0', 10);
        var ctype = form.getAttribute('data-ctype') || '';
        var cid = parseInt((cidInput && cidInput.value) || '0', 10);
        if (!bid || !ctype) {
            toast('error', 'Comment failed', 'Missing comment context.');
            return;
        }
        var submitBtn = /** @type {HTMLButtonElement|null} */ (form.querySelector('button[type="submit"]'));
        setBusy(submitBtn, true);
        var action = cid > 0 ? A.BansEditComment : A.BansAddComment;
        a.call(action, {
            bid: bid,
            cid: cid,
            ctype: ctype,
            ctext: value,
            page: -1,
        }).then(function (r) {
            if (!r) {
                setBusy(submitBtn, false);
                return;
            }
            if (r.redirect) return;
            if (r.ok === false) {
                setBusy(submitBtn, false);
                var em = (r.error && r.error.message) || 'Failed to save comment.';
                toast('error', 'Comment failed', em);
                return;
            }
            var data = r.data || {};
            var msg = data.message || {};
            toast('success', msg.title || 'Comment saved', msg.body || 'The comment was saved.');
            window.location.reload();
        }).catch(function (e) {
            setBusy(submitBtn, false);
            toast('error', 'Comment failed', String(e && e.message ? e.message : e));
        });
    }

    /**
     * @param {{cid: number, ctype: string, page: number, trigger: HTMLElement}} ctx
     */
    function runDelete(ctx) {
        var a = api(), A = actions();
        if (!a || !A) {
            toast('error', 'Delete failed', 'The API client is unavailable. Reload the page and try again.');
            return;
        }

        var submitBtn = /** @type {HTMLButtonElement|null} */ (
            document.querySelector('#comment-delete-dialog [data-testid="comment-delete-submit"]')
        );
        setBusy(submitBtn, true);
        setBusy(ctx.trigger, true);
        a.call(A.BansRemoveComment, {
            cid:   ctx.cid,
            ctype: ctx.ctype,
            page:  ctx.page,
        }).then(function (r) {
            // sb.api.call follows r.redirect natively when the envelope
            // sets it; on success api_bans_remove_comment surfaces a
            // `message.redir` field that drives the navigation back to
            // the same paginated view. Mirror SbppGroupsAdd's shape.
            if (!r) {
                setBusy(submitBtn, false);
                setBusy(ctx.trigger, false);
                return;
            }
            if (r.redirect) return;
            if (r.ok === false) {
                setBusy(submitBtn, false);
                setBusy(ctx.trigger, false);
                var em = (r.error && r.error.message) || 'Failed to delete comment.';
                toast('error', 'Delete failed', em);
                return;
            }
            var data = r.data || {};
            var msg = data.message || {};
            var inList = ctx.ctype === 'B' || ctx.ctype === 'C';
            closeDeleteDialog();
            toast('success', msg.title || 'Comment Deleted', msg.body || 'The comment was deleted.');
            if (inList) {
                document.dispatchEvent(new CustomEvent('sbpp:comment-deleted', {
                    detail: { cid: ctx.cid, ctype: ctx.ctype },
                }));
                setBusy(submitBtn, false);
                return;
            }
            // Queue cards (S / P): honour the handler's redir envelope
            // (sb.api.call only auto-redirects on r.redirect, NOT on
            // data.message.redir). Pause so the toast is visible first.
            setTimeout(function () {
                if (msg.redir) window.location.href = msg.redir;
                else window.location.reload();
            }, 1200);
        }).catch(function (err) {
            setBusy(submitBtn, false);
            setBusy(ctx.trigger, false);
            toast('error', 'Delete failed', String(err && err.message ? err.message : err));
        });
    }

    document.addEventListener('click', function (e) {
        var t = /** @type {Element|null} */ (e.target);
        if (!t) return;

        if (t.closest && t.closest('[data-testid="comment-delete-cancel"]')) {
            e.preventDefault();
            closeDeleteDialog();
            return;
        }

        var composeTrigger = /** @type {HTMLElement|null} */ (t.closest && t.closest('[data-action="comment-compose"]'));
        if (composeTrigger) {
            e.preventDefault();
            openQueueComposer(composeTrigger);
            return;
        }

        var cancelComposer = /** @type {HTMLElement|null} */ (t.closest && t.closest('[data-comment-composer] [data-comment-cancel]'));
        if (cancelComposer) {
            e.preventDefault();
            var form = /** @type {HTMLFormElement|null} */ (cancelComposer.closest('[data-comment-composer]'));
            if (form) showComposer(form, false);
            return;
        }

        var trigger = /** @type {HTMLElement|null} */ (t.closest && t.closest('[data-action="comment-delete"]'));
        if (!trigger) return;
        e.preventDefault();

        var cid = parseInt(trigger.getAttribute('data-cid') || '0', 10);
        var ctype = trigger.getAttribute('data-ctype') || '';
        var page = parseInt(trigger.getAttribute('data-page') || '-1', 10);

        if (!cid || !ctype) {
            toast('error', 'Delete failed', 'Missing comment context.');
            return;
        }

        openDeleteDialog({ cid: cid, ctype: ctype, page: page, trigger: trigger });
    });

    document.addEventListener('submit', function (e) {
        var form = /** @type {Element|null} */ (e.target);
        if (!form || !(/** @type {Element} */ (form)).closest) return;
        if (form.matches('[data-testid="comment-delete-form"]')) {
            e.preventDefault();
            if (!pending) return;
            runDelete(pending);
            return;
        }
        if (form.matches('[data-comment-composer]')) {
            e.preventDefault();
            submitQueueComposer(/** @type {HTMLFormElement} */ (form));
        }
    });

    document.addEventListener('cancel', function (e) {
        var t = /** @type {Element|null} */ (e.target);
        if (!t || t.id !== 'comment-delete-dialog') return;
        pending = null;
    });
})();
