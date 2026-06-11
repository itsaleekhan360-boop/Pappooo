/*
 * Shopify UTM tracking
 * --------------------
 * Captures UTM (+ click ID) params from the landing URL, persists them, and
 * attaches them to the Shopify CART so they appear on the ORDER in admin
 * (Order > Additional details / note_attributes). This method survives the
 * move to checkout extensibility — no checkout.liquid edits required.
 *
 * Install:
 *   1. Add this file as a theme asset: assets/utm-tracking.js
 *   2. In layout/theme.liquid, before </head>:
 *        {{ 'utm-tracking.js' | asset_url | script_tag }}
 *      (or paste the IIFE below inside a <script> tag there directly).
 */
(function () {
  'use strict';

  /* ---------------- Config ---------------- */
  var PARAMS      = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'gclid', 'fbclid'];
  var STORAGE_KEY = 'utm_attribution';
  var TTL_DAYS    = 30;
  var FIRST_TOUCH = true;   // true = keep the original source; false = always use the latest visit

  /* ---------------- Helpers ---------------- */
  function getParams() {
    var qs = new URLSearchParams(window.location.search);
    var found = {};
    PARAMS.forEach(function (k) { var v = qs.get(k); if (v) found[k] = v; });
    return found;
  }

  function readStore() {
    try {
      var data = JSON.parse(localStorage.getItem(STORAGE_KEY));
      if (data && data.expires && Date.now() > data.expires) {
        localStorage.removeItem(STORAGE_KEY);
        return null;
      }
      return data;
    } catch (e) { return null; }
  }

  function writeStore(values) {
    var data = {
      values: values,
      landing_page: window.location.pathname + window.location.search,
      referrer: document.referrer || '(direct)',
      first_seen: new Date().toISOString(),
      expires: Date.now() + TTL_DAYS * 86400000
    };
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(data)); } catch (e) {}
    document.cookie = STORAGE_KEY + '=' + encodeURIComponent(JSON.stringify(values)) +
      ';path=/;max-age=' + (TTL_DAYS * 86400) + ';SameSite=Lax';
    return data;
  }

  /* ---------------- 1. Capture / persist ---------------- */
  var incoming = getParams();
  var stored   = readStore();
  var attribution;

  if (Object.keys(incoming).length) {
    // Keep the first touch if one already exists, otherwise store this visit.
    attribution = (FIRST_TOUCH && stored && stored.values && stored.values.utm_source)
      ? stored
      : writeStore(incoming);
  } else {
    attribution = stored;   // no params this visit — reuse what we have
  }

  if (!attribution || !attribution.values) return;
  var utm = attribution.values;

  window.UTM = attribution;  // expose globally for any custom use

  /* ---------------- 2. Push to GTM dataLayer ---------------- */
  window.dataLayer = window.dataLayer || [];
  window.dataLayer.push(Object.assign({ event: 'utm_attribution' }, utm));

  /* ---------------- 3. Fill hidden form fields ----------------
   * Add inputs to any form (Klaviyo, contact, newsletter) like:
   *   <input type="hidden" data-utm="utm_source">
   */
  function fillForms() {
    document.querySelectorAll('[data-utm]').forEach(function (el) {
      var key = el.getAttribute('data-utm');
      if (utm[key]) el.value = utm[key];
    });
  }
  if (document.readyState !== 'loading') fillForms();
  else document.addEventListener('DOMContentLoaded', fillForms);

  /* ---------------- 4. Attach to the Shopify order ----------------
   * Cart attributes persist on the cart (even when empty) and carry
   * through checkout to the order's "Additional details".
   */
  function syncCart() {
    var attrs = Object.assign({}, utm, {
      landing_page: attribution.landing_page,
      referrer: attribution.referrer
    });

    fetch('/cart.js', { headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.json(); })
      .then(function (cart) {
        var current = cart.attributes || {};
        var changed = Object.keys(attrs).some(function (k) { return current[k] !== attrs[k]; });
        if (!changed) return;  // avoid redundant writes on every page load
        return fetch('/cart/update.js', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
          body: JSON.stringify({ attributes: attrs })
        });
      })
      .catch(function () { /* fail silently */ });
  }
  syncCart();
})();