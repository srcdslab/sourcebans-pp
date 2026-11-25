// @ts-check
/* ============================================================
   passkeys.js — WebAuthn glue for passkeys (#108)

   The server sends WebAuthn options as JSON with base64url strings
   (web-auth/webauthn-lib's serializer); navigator.credentials wants
   ArrayBuffers, and its answer goes back as JSON with base64url
   strings. This file does both conversions and nothing else: the
   server checks everything (challenge, origin, RP ID, signature,
   user verification, counter).

   Exposes window.SBPP_PASSKEYS = { supported, create, get }.
   ============================================================ */
(function () {
    'use strict';

    /** @param {string} s @returns {ArrayBuffer} */
    function fromB64url(s) {
        var b64 = s.replace(/-/g, '+').replace(/_/g, '/');
        b64 += '='.repeat((4 - (b64.length % 4)) % 4);
        var bin = atob(b64);
        var out = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out.buffer;
    }

    /** @param {ArrayBuffer | null} buf @returns {string | null} */
    function toB64url(buf) {
        if (!buf) return null;
        var bytes = new Uint8Array(buf);
        var bin = '';
        for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    /** @returns {boolean} */
    function supported() {
        return typeof window.PublicKeyCredential === 'function' && !!navigator.credentials;
    }

    /**
     * @param {any} list
     * @returns {PublicKeyCredentialDescriptor[]}
     */
    function descriptors(list) {
        if (!Array.isArray(list)) return [];
        return list.map(function (/** @type {any} */ c) {
            /** @type {PublicKeyCredentialDescriptor} */
            var d = { type: 'public-key', id: fromB64url(String(c.id)) };
            if (Array.isArray(c.transports)) d.transports = c.transports;
            return d;
        });
    }

    /**
     * Register a passkey from server creation options.
     * @param {any} options
     * @returns {Promise<Record<string, unknown>>}
     */
    async function create(options) {
        /** @type {PublicKeyCredentialCreationOptions} */
        var publicKey = {
            rp: options.rp,
            user: { id: fromB64url(String(options.user.id)), name: String(options.user.name), displayName: String(options.user.displayName) },
            challenge: fromB64url(String(options.challenge)),
            pubKeyCredParams: options.pubKeyCredParams,
            timeout: options.timeout,
            excludeCredentials: descriptors(options.excludeCredentials),
            authenticatorSelection: options.authenticatorSelection,
            attestation: options.attestation || 'none'
        };
        var cred = /** @type {PublicKeyCredential | null} */ (await navigator.credentials.create({ publicKey: publicKey }));
        if (!cred) throw new Error('No passkey was created.');
        var res = /** @type {AuthenticatorAttestationResponse} */ (cred.response);
        return {
            id: cred.id,
            rawId: toB64url(cred.rawId),
            type: cred.type,
            response: {
                clientDataJSON: toB64url(res.clientDataJSON),
                attestationObject: toB64url(res.attestationObject),
                transports: typeof res.getTransports === 'function' ? res.getTransports() : []
            },
            clientExtensionResults: cred.getClientExtensionResults()
        };
    }

    /**
     * Sign in with a passkey from server request options.
     * @param {any} options
     * @returns {Promise<Record<string, unknown>>}
     */
    async function get(options) {
        /** @type {PublicKeyCredentialRequestOptions} */
        var publicKey = {
            challenge: fromB64url(String(options.challenge)),
            rpId: options.rpId,
            timeout: options.timeout,
            allowCredentials: descriptors(options.allowCredentials),
            userVerification: options.userVerification || 'required'
        };
        var cred = /** @type {PublicKeyCredential | null} */ (await navigator.credentials.get({ publicKey: publicKey }));
        if (!cred) throw new Error('No passkey was used.');
        var res = /** @type {AuthenticatorAssertionResponse} */ (cred.response);
        return {
            id: cred.id,
            rawId: toB64url(cred.rawId),
            type: cred.type,
            response: {
                clientDataJSON: toB64url(res.clientDataJSON),
                authenticatorData: toB64url(res.authenticatorData),
                signature: toB64url(res.signature),
                userHandle: toB64url(res.userHandle)
            },
            clientExtensionResults: cred.getClientExtensionResults()
        };
    }

    window.SBPP_PASSKEYS = { supported: supported, create: create, get: get };
}());
