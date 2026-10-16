#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build n8n workflow 'Shopee Review Monitor' (main) và mirror-test variant."""
import json, copy, sys, os

OUT_DIR = os.path.dirname(os.path.abspath(__file__))

# ===================== JS CODE SNIPPETS =====================

SHA_IMPL = r"""
function utf8Bytes(str) {
  if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(str);
  const out = [];
  for (let i = 0; i < str.length; i++) {
    let c = str.charCodeAt(i);
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
    else if (c >= 0xd800 && c <= 0xdbff) {
      const c2 = str.charCodeAt(++i);
      c = 0x10000 + ((c & 0x3ff) << 10) + (c2 & 0x3ff);
      out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 0x3f), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    } else out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
  }
  return Uint8Array.from(out);
}
const K = [
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
];
function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
function sha256Bytes(msgBytes) {
  const len = msgBytes.length;
  const bitLen = len * 8;
  const data = new Uint8Array((((len + 8) >> 6) + 1) * 64);
  data.set(msgBytes);
  data[len] = 0x80;
  const dv = new DataView(data.buffer);
  dv.setUint32(data.length - 4, bitLen >>> 0, false);
  dv.setUint32(data.length - 8, Math.floor(bitLen / 0x100000000), false);
  const H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  const w = new Uint32Array(64);
  for (let off = 0; off < data.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >>> 3);
      const s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >>> 10);
      w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0;
    }
    let a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0]=(H[0]+a)>>>0; H[1]=(H[1]+b)>>>0; H[2]=(H[2]+c)>>>0; H[3]=(H[3]+d)>>>0;
    H[4]=(H[4]+e)>>>0; H[5]=(H[5]+f)>>>0; H[6]=(H[6]+g)>>>0; H[7]=(H[7]+h)>>>0;
  }
  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  H.forEach(function (v, i) { odv.setUint32(i * 4, v, false); });
  return out;
}
function bytesToHex(b) { return Array.from(b).map(function (x) { return x.toString(16).padStart(2, '0'); }).join(''); }
function hmacSha256Hex(keyStr, msgStr) {
  let key = utf8Bytes(keyStr);
  if (key.length > 64) key = sha256Bytes(key);
  const ipad = new Uint8Array(64);
  const opad = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    const kb = i < key.length ? key[i] : 0;
    ipad[i] = kb ^ 0x36;
    opad[i] = kb ^ 0x5c;
  }
  const innerHash = sha256Bytes(Uint8Array.from([...ipad, ...utf8Bytes(msgStr)]));
  return bytesToHex(sha256Bytes(Uint8Array.from([...opad, ...innerHash])));
}
"""

S_INIT = r"""
const sd = $getWorkflowStaticData('global');
sd.shops = [];
sd.productChecks = [];
sd.run_errors = [];
sd.counts = { products: 0, reviews_new: 0, analyses_done: 0, analyses_failed: 0 };
sd.cur = null;
sd.run_started_at = new Date().toISOString();
return [{ json: { started_at: sd.run_started_at } }];
"""

S_FILTER_SHOPS = r"""
const cfg = $('Config').first().json;
const rows = $input.all().map(function (i) { return i.json; }).filter(function (r) { return r && (r.shop_url || r.shop_id); });
function parseShopId(r) {
  if (r.shop_id !== undefined && r.shop_id !== null && String(r.shop_id).trim() !== '') return String(r.shop_id).trim();
  const url = String(r.shop_url || '');
  const m = url.match(/\/shop\/(\d+)/) || url.match(/-s\.(\d+)/) || url.match(/\.s\.(\d+)/);
  return m ? m[1] : '';
}
function yes(v) {
  const s = String(v === undefined || v === null ? '' : v).trim().toLowerCase();
  return ['true','1','yes','y','on'].indexOf(s) !== -1;
}
const sd = $getWorkflowStaticData('global');
const out = [];
const seen = {};
let skipped = 0;
for (let i = 0; i < rows.length; i++) {
  const r = rows[i];
  if (!yes(r.enabled)) continue;
  const shop_id = parseShopId(r);
  if (!shop_id) { skipped++; continue; }
  if (seen[shop_id]) continue;
  seen[shop_id] = true;
  out.push({ json: {
    shop_id: shop_id,
    shop_name: r.shop_name || '',
    shop_url: r.shop_url || '',
    enabled: 'true',
    last_checked_at: '',
    status: 'pending',
    error_message: ''
  }, pairedItem: { item: 0 } });
}
sd.counts.shops_skipped = skipped;
const maxShops = Number(cfg.MAX_SHOPS) || 10;
return out.slice(0, maxShops);
"""

S_BUILD_PRODUCT_SIGN = SHA_IMPL + r"""
const cfg = $('Config').first().json;
const shop = $json;
const path = '/api/v2/product/get_item_list';
const timestamp = Math.floor(Date.now() / 1000);
const partner_id = String(cfg.SHOPEE_PARTNER_ID || '');
const access_token = String(cfg.SHOPEE_ACCESS_TOKEN || '');
const shop_id = String(shop.shop_id || '');
const base = partner_id + path + timestamp + access_token + shop_id;
const sign = hmacSha256Hex(String(cfg.SHOPEE_PARTNER_KEY || ''), base);
const out = {};
for (const k in shop) { if (Object.prototype.hasOwnProperty.call(shop, k)) out[k] = shop[k]; }
out._path = path;
out._timestamp = timestamp;
out._partner_id = partner_id;
out._access_token = access_token;
out._shop_id = shop_id;
out._sign = sign;
return [{ json: out, pairedItem: { item: 0 } }];
"""

S_MAP_API_PRODUCTS = r"""
const body = $json && typeof $json === 'object' ? $json : {};
const err = body.error !== undefined ? body.error : (body.response ? body.response.error : undefined);
let items = body.item !== undefined ? body.item : ((body.response && body.response.item) || body.items || (body.response && body.response.items) || []);
if (err !== undefined && err !== null && err !== '' && err !== 0 && err !== '0') {
  throw new Error('Shopee get_item_list error: ' + JSON.stringify(err) + ' ' + String(body.message || ''));
}
if (!Array.isArray(items)) throw new Error('Phan hoi get_item_list khong dung dinh dang: ' + JSON.stringify(body).slice(0, 300));
let ctx = {};
try { ctx = $('Loop Over Shops').item.json; } catch (e) { ctx = $input.first() ? $input.first().json : {}; }
const out = [];
for (let i = 0; i < items.length; i++) {
  const it = items[i] || {};
  const rawId = it.item_id !== undefined ? it.item_id : (it.itemid !== undefined ? it.itemid : '');
  const item_id = String(rawId).trim();
  if (!item_id) continue;
  out.push({ json: {
    shop_id: String(ctx.shop_id || it.shop_id || ''),
    shop_name: ctx.shop_name || '',
    item_id: item_id,
    product_name: it.item_name || it.name || '',
    product_url: ''
  }, pairedItem: { item: 0 } });
}
if (out.length === 0) {
  return [{ json: { _marker: 'no_products', shop_id: String(ctx.shop_id || ''), shop_name: ctx.shop_name || '' }, pairedItem: { item: 0 } }];
}
return out;
"""

S_NORMALIZE_PRODUCTS = r"""
const cfg = $('Config').first().json;
let shop = {};
try { shop = $('Loop Over Shops').item.json; } catch (e) { shop = $input.first() ? $input.first().json : {}; }
const sd = $getWorkflowStaticData('global');
const rows = $input.all().map(function (i) { return i.json; }).filter(function (r) {
  return r && !r._marker && r.item_id !== undefined && r.item_id !== null && String(r.item_id).trim() !== '';
});
const seen = {};
const out = [];
const maxProducts = Number(cfg.MAX_PRODUCTS_PER_SHOP) || 20;
for (let i = 0; i < rows.length; i++) {
  const r = rows[i];
  const item_id = String(r.item_id).trim();
  if (seen[item_id]) continue;
  seen[item_id] = true;
  let product_url = r.product_url || '';
  const sid = String(r.shop_id || shop.shop_id || '');
  if (!product_url && sid && item_id) product_url = 'https://shopee.vn/product/' + sid + '/' + item_id;
  out.push({ json: {
    shop_id: sid,
    shop_name: r.shop_name || shop.shop_name || '',
    item_id: item_id,
    product_name: r.product_name || '',
    product_url: product_url,
    last_review_check: '',
    status: 'pending'
  }, pairedItem: { item: 0 } });
  if (out.length >= maxProducts) break;
}
const shopRow = {
  shop_id: String(shop.shop_id || (out[0] ? out[0].json.shop_id : '') || ''),
  status: 'ok',
  last_checked_at: new Date().toISOString(),
  error_message: ''
};
sd.shops.push(shopRow);
if (out.length === 0) {
  return [{ json: { _marker: 'no_products', shop_id: shopRow.shop_id, shop_name: shop.shop_name || '' }, pairedItem: { item: 0 } }];
}
return out;
"""

S_SHOP_ERROR = r"""
function errMsg(e) {
  if (e === undefined || e === null || e === '') return 'unknown error';
  if (typeof e === 'string') return e;
  if (typeof e === 'object') {
    if (typeof e.message === 'string' && e.message) return e.message;
    try { return JSON.stringify(e); } catch (err) { return String(e); }
  }
  return String(e);
}
const sd = $getWorkflowStaticData('global');
let shop = {};
if ($json && $json.shop_id) { shop = $json; }
else { try { shop = $('Loop Over Shops').item.json; } catch (e) { shop = {}; } }
const msg = errMsg($json && $json.error).slice(0, 500);
const row = {
  shop_id: String(shop.shop_id || ''),
  status: 'error',
  last_checked_at: new Date().toISOString(),
  error_message: msg
};
sd.shops.push(row);
sd.run_errors.push({ scope: 'shop', key: row.shop_id, message: msg });
return [{ json: { shop_id: row.shop_id, status: 'error', error_message: msg }, pairedItem: { item: 0 } }];
"""

S_COLLECT_PRODUCTS = r"""
const sd = $getWorkflowStaticData('global');
const seen = {};
const out = [];
const all = $input.all();
for (let i = 0; i < all.length; i++) {
  const r = all[i].json;
  if (!r || r._marker || r.item_id === undefined || r.item_id === null || String(r.item_id).trim() === '') continue;
  const shop_id = String(r.shop_id || '');
  const item_id = String(r.item_id).trim();
  const key = shop_id + '_' + item_id;
  if (seen[key]) continue;
  seen[key] = true;
  out.push({ json: {
    shop_id: shop_id,
    shop_name: r.shop_name || '',
    item_id: item_id,
    product_name: r.product_name || '',
    product_url: r.product_url || '',
    last_review_check: '',
    status: 'pending'
  }, pairedItem: { item: i } });
}
sd.counts.products = out.length;
if (out.length === 0) return [{ json: { _marker: 'no_products' }, pairedItem: { item: 0 } }];
return out;
"""

S_THROTTLE = r"""
const cfg = $('Config').first().json;
const ms = Math.max(0, Number(cfg.REQUEST_DELAY_MS) || 0);
if (ms > 0) await new Promise(function (resolve) { setTimeout(resolve, Math.min(ms, 10000)); });
return $input.all();
"""

S_BUILD_STATE = r"""
const rows = $input.all().map(function (i) { return i.json; }).filter(function (r) { return r && r.review_key; });
let product = {};
try { product = $('Loop Over Products').item.json; } catch (e) { product = rows[0] || {}; }
const existing_keys = [];
const pending = [];
for (let i = 0; i < rows.length; i++) {
  const r = rows[i];
  existing_keys.push(String(r.review_key));
  if (String(r.analysis_status || '').toLowerCase() === 'pending') pending.push(r);
}
return [{ json: {
  shop_id: String(product.shop_id || (rows[0] ? rows[0].shop_id : '') || ''),
  shop_name: product.shop_name || '',
  item_id: String(product.item_id || (rows[0] ? rows[0].item_id : '') || ''),
  product_name: product.product_name || '',
  existing_keys: existing_keys,
  pending: pending
}, pairedItem: { item: 0 } }];
"""

S_INIT_FETCH = r"""
const sd = $getWorkflowStaticData('global');
let state = {};
try { state = $('Code - Build Product State').item.json; } catch (e) { state = $json || {}; }
sd.cur = { acc: [], cursor: 0, page: 1, done: false };
return [{ json: {
  shop_id: String(state.shop_id || ''),
  shop_name: state.shop_name || '',
  item_id: String(state.item_id || ''),
  product_name: state.product_name || ''
}, pairedItem: { item: 0 } }];
"""

S_REVIEW_SIGN = SHA_IMPL + r"""
const cfg = $('Config').first().json;
const sd = $getWorkflowStaticData('global');
const cur = sd.cur || { acc: [], cursor: 0, page: 1 };
const path = '/api/v2/product/get_comment';
const timestamp = Math.floor(Date.now() / 1000);
const partner_id = String(cfg.SHOPEE_PARTNER_ID || '');
const access_token = String(cfg.SHOPEE_ACCESS_TOKEN || '');
const shop_id = String($json.shop_id || '');
const base = partner_id + path + timestamp + access_token + shop_id;
const sign = hmacSha256Hex(String(cfg.SHOPEE_PARTNER_KEY || ''), base);
return [{ json: {
  shop_id: shop_id,
  shop_name: $json.shop_name || '',
  item_id: String($json.item_id || ''),
  product_name: $json.product_name || '',
  _timestamp: timestamp,
  _partner_id: partner_id,
  _access_token: access_token,
  _shop_id: shop_id,
  _sign: sign,
  _cursor: cur.cursor,
  _page: cur.page
}, pairedItem: { item: 0 } }];
"""

S_PARSE_COMMENTS = r"""
const sd = $getWorkflowStaticData('global');
const cur = sd.cur || { acc: [], cursor: 0, page: 1 };
const body = $json && typeof $json === 'object' ? $json : {};
const err = body.error !== undefined ? body.error : (body.response ? body.response.error : undefined);
if (err !== undefined && err !== null && err !== '' && err !== 0 && err !== '0') {
  throw new Error('Shopee get_comment error: ' + JSON.stringify(err) + ' ' + String(body.message || ''));
}
let list = body.item_comment_list !== undefined ? body.item_comment_list : ((body.response && body.response.item_comment_list) || body.comments || []);
if (!Array.isArray(list)) throw new Error('Phan hoi get_comment khong dung dinh dang: ' + JSON.stringify(body).slice(0, 300));
const cfg = $('Config').first().json;
let state = {};
try { state = $('Code - Build Product State').item.json; } catch (e) { state = {}; }
const known = {};
(state.existing_keys || []).forEach(function (k) { known[String(k)] = true; });
const maxReviews = Number(cfg.MAX_REVIEWS_PER_PRODUCT) || 50;
const pageSize = Number(cfg.REVIEW_PAGE_SIZE) || 20;
const maxPages = Number(cfg.MAX_REVIEW_PAGES) || 3;
const prefix = String(state.shop_id || '') + '_' + String(state.item_id || '') + '_';
let hitKnown = false;
for (let i = 0; i < list.length; i++) {
  const c = list[i] || {};
  const raw = c.comment_id !== undefined ? c.comment_id : (c.cid !== undefined ? c.cid : '');
  const comment_id = String(raw).trim();
  if (!comment_id) continue;
  if (known[prefix + comment_id]) { hitKnown = true; continue; }
  cur.acc.push(c);
}
let nextCursor = cur.cursor;
if (list.length > 0) {
  const last = list[list.length - 1] || {};
  const rawLast = last.comment_id !== undefined ? last.comment_id : (last.cid !== undefined ? last.cid : '');
  const lastId = String(rawLast);
  if (lastId && lastId !== 'undefined') nextCursor = lastId;
}
cur.cursor = nextCursor;
const enough = cur.acc.length >= maxReviews;
const morePages = list.length >= pageSize && cur.page < maxPages;
cur.page = cur.page + 1;
const more = morePages && !hitKnown && !enough;
sd.cur = cur;
return [{ json: {
  shop_id: String(state.shop_id || ''),
  item_id: String(state.item_id || ''),
  _more: more ? 'yes' : 'no',
  _count: list.length,
  _page: cur.page
}, pairedItem: { item: 0 } }];
"""

S_COLLECT_API = r"""
const sd = $getWorkflowStaticData('global');
const cur = sd.cur || { acc: [] };
let state = {};
try { state = $('Code - Build Product State').item.json; } catch (e) { state = $json || {}; }
const out = [];
for (let i = 0; i < cur.acc.length; i++) {
  const c = cur.acc[i] || {};
  const merged = {};
  for (const k in c) { if (Object.prototype.hasOwnProperty.call(c, k)) merged[k] = c[k]; }
  merged.__shop_id = String(state.shop_id || '');
  merged.__shop_name = state.shop_name || '';
  merged.__item_id = String(state.item_id || '');
  merged.__product_name = state.product_name || '';
  out.push({ json: merged, pairedItem: { item: 0 } });
}
if (out.length === 0) return [{ json: { _marker: 'no_api_reviews' }, pairedItem: { item: 0 } }];
return out;
"""

S_NORMALIZE_REVIEWS = r"""
let state = {};
try { state = $('Code - Build Product State').item.json; } catch (e) { state = {}; }
function normTime(v) {
  if (v === undefined || v === null || v === '') return '';
  const s = String(v).trim();
  if (/^\d{9,13}$/.test(s)) {
    const n = Number(s);
    const ms = n < 1e12 ? n * 1000 : n;
    const d = new Date(ms);
    return isNaN(d.getTime()) ? '' : d.toISOString();
  }
  const d = new Date(s);
  if (!isNaN(d.getTime())) return d.toISOString();
  return s;
}
const rows = $input.all().map(function (i) { return i.json; });
const out = [];
for (let i = 0; i < rows.length; i++) {
  const r = rows[i];
  if (!r || r._marker) continue;
  const rawId = r.comment_id !== undefined ? r.comment_id : (r.cid !== undefined ? r.cid : '');
  const comment_id = String(rawId).trim();
  if (!comment_id) continue;
  const timeRaw = r.review_time !== undefined ? r.review_time : (r.ctime !== undefined ? r.ctime : (r.c_time !== undefined ? r.c_time : r.create_time));
  out.push({ json: {
    shop_id: String(r.shop_id || r.__shop_id || state.shop_id || ''),
    shop_name: r.shop_name || r.__shop_name || state.shop_name || '',
    item_id: String(r.item_id || r.__item_id || state.item_id || ''),
    product_name: r.product_name || r.__product_name || state.product_name || '',
    comment_id: comment_id,
    rating_star: (r.rating_star !== undefined && r.rating_star !== null && r.rating_star !== '') ? Number(r.rating_star) : '',
    comment: String(r.comment !== undefined ? r.comment : (r.content !== undefined ? r.content : '')),
    review_time: normTime(timeRaw),
    collected_at: new Date().toISOString()
  }, pairedItem: { item: 0 } });
}
if (out.length === 0) {
  return [{ json: { _marker: 'no_reviews', shop_id: String(state.shop_id || ''), item_id: String(state.item_id || '') }, pairedItem: { item: 0 } }];
}
return out;
"""

S_DEDUP_REVIEWS = r"""
const cfg = $('Config').first().json;
let state = {};
try { state = $('Code - Build Product State').item.json; } catch (e) { state = {}; }
const existing = {};
(state.existing_keys || []).forEach(function (k) { existing[String(k)] = true; });
const rows = $input.all().map(function (i) { return i.json; }).filter(function (r) { return r && r.comment_id; });
const max = Number(cfg.MAX_REVIEWS_PER_PRODUCT) || 50;
const seen = {};
const out = [];
for (let i = 0; i < rows.length; i++) {
  const r = rows[i];
  const comment_id = String(r.comment_id).trim();
  const shop_id = String(r.shop_id || state.shop_id || '');
  const item_id = String(r.item_id || state.item_id || '');
  if (!comment_id || !shop_id || !item_id) continue;
  const review_key = shop_id + '_' + item_id + '_' + comment_id;
  if (existing[review_key] || seen[review_key]) continue;
  seen[review_key] = true;
  out.push({ json: {
    review_key: review_key,
    shop_id: shop_id,
    shop_name: r.shop_name || state.shop_name || '',
    item_id: item_id,
    product_name: r.product_name || state.product_name || '',
    comment_id: comment_id,
    rating_star: r.rating_star,
    comment: r.comment,
    review_time: r.review_time,
    collected_at: r.collected_at,
    sentiment: '',
    issues: '',
    summary: '',
    urgency: '',
    analysis_status: 'pending'
  }, pairedItem: { item: 0 } });
  if (out.length >= max) break;
}
if (out.length === 0) {
  return [{ json: { _marker: 'no_new_reviews', shop_id: String(state.shop_id || ''), item_id: String(state.item_id || '') }, pairedItem: { item: 0 } }];
}
return out;
"""

S_BUILD_QUEUE = r"""
const cfg = $('Config').first().json;
let state = {};
try { state = $('Code - Build Product State').item.json; } catch (e) { state = $json || {}; }
const sd = $getWorkflowStaticData('global');
const check = {
  shop_id: String(state.shop_id || ''),
  item_id: String(state.item_id || ''),
  product_name: state.product_name || '',
  last_review_check: new Date().toISOString(),
  status: 'ok'
};
sd.productChecks = (sd.productChecks || []).filter(function (c) {
  return String(c.shop_id) + '_' + String(c.item_id) !== check.shop_id + '_' + check.item_id;
});
sd.productChecks.push(check);
const saved = $input.all().map(function (i) { return i.json; }).filter(function (r) { return r && r.review_key; });
sd.counts.reviews_new += saved.length;
const pendingOld = (state.pending || []).filter(function (r) {
  return String(r.analysis_status || '').toLowerCase() === 'pending';
});
const all = pendingOld.concat(saved);
const queue = [];
const seen = {};
for (let i = 0; i < all.length; i++) {
  const r = all[i];
  const k = String(r.review_key || '');
  if (!k || seen[k]) continue;
  seen[k] = true;
  queue.push({ json: {
    review_key: k,
    shop_id: String(r.shop_id || state.shop_id || ''),
    shop_name: r.shop_name || state.shop_name || '',
    item_id: String(r.item_id || state.item_id || ''),
    product_name: r.product_name || state.product_name || '',
    comment_id: String(r.comment_id || ''),
    rating_star: r.rating_star !== undefined ? r.rating_star : '',
    comment: String(r.comment || ''),
    review_time: r.review_time || '',
    collected_at: r.collected_at || ''
  }, pairedItem: { item: 0 } });
}
const maxAi = Number(cfg.MAX_AI_PER_PRODUCT) || 10;
const finalQueue = queue.slice(0, maxAi);
if (finalQueue.length === 0) {
  return [{ json: { _marker: 'no_queue', shop_id: check.shop_id, item_id: check.item_id }, pairedItem: { item: 0 } }];
}
return finalQueue;
"""

S_PAYLOAD = r"""
const cfg = $('Config').first().json;
const r = $json;
const system = 'Bạn là bộ phân tích đánh giá sản phẩm Shopee. Chỉ trả về MỘT đối tượng JSON hợp lệ, không kèm văn bản nào khác, đúng cấu trúc: {"sentiment":"positive|neutral|negative","issues":["quality"|"packaging"|"delivery"|"price"|"customer_service"|"other",...],"summary":"...","urgency":"low"|"medium"|"high"}. Quy tắc: - sentiment: cảm xúc của người viết bình luận (positive, neutral hoặc negative). - issues: chỉ chọn các giá trị trong danh sách: quality, packaging, delivery, price, customer_service, other; nếu bình luận không nêu rõ vấn đề thì để mảng rỗng []. - summary: tóm tắt đúng nội dung bình luận trong 1 câu, cùng ngôn ngữ với bình luận. - urgency: low nếu chỉ khen hoặc nhận xét chung chung, medium nếu có phàn nàn, high nếu yêu cầu khiếu nại hoặc hoàn tiền. - Chỉ dùng thông tin có trong bình luận, không bịa thêm thông tin.';
const stars = (r.rating_star !== undefined && r.rating_star !== null && r.rating_star !== '') ? String(r.rating_star) + '/5' : 'không rõ';
const user = 'Điểm đánh giá: ' + stars + '\nBình luận: ' + String(r.comment || '').slice(0, 1500);
return [{ json: {
  review_key: String(r.review_key || ''),
  payload: {
    model: cfg.OLLAMA_MODEL || 'qwen2.5-coder:1.5b',
    stream: false,
    format: 'json',
    options: { temperature: 0.1 },
    messages: [
      { role: 'system', content: system },
      { role: 'user', content: user }
    ]
  }
}, pairedItem: { item: 0 } }];
"""

S_PARSE_ANALYSIS = r"""
const ALLOWED = ['quality', 'packaging', 'delivery', 'price', 'customer_service', 'other'];
const sd = $getWorkflowStaticData('global');
const raw = String(($json && $json.message && $json.message.content) || '');
let parsed = null;
try { parsed = JSON.parse(raw); } catch (e) {
  const m = raw.match(/\{[\s\S]*\}/);
  if (m) { try { parsed = JSON.parse(m[0]); } catch (e2) {} }
}
if (!parsed || typeof parsed !== 'object') throw new Error('Ollama khong tra JSON hop le: ' + raw.slice(0, 200));
const sentiment = String(parsed.sentiment || '').toLowerCase().trim();
if (['positive', 'neutral', 'negative'].indexOf(sentiment) === -1) throw new Error('Gia tri sentiment khong hop le: ' + String(parsed.sentiment));
const urgency = String(parsed.urgency || '').toLowerCase().trim();
if (['low', 'medium', 'high'].indexOf(urgency) === -1) throw new Error('Gia tri urgency khong hop le: ' + String(parsed.urgency));
let issues = Array.isArray(parsed.issues) ? parsed.issues : [];
issues = issues.map(function (x) {
  const v = String(x).toLowerCase().trim();
  return ALLOWED.indexOf(v) !== -1 ? v : 'other';
});
issues = issues.filter(function (v, i, a) { return a.indexOf(v) === i; });
const summary = String(parsed.summary || '').replace(/\s+/g, ' ').trim().slice(0, 500);
let review = {};
try { review = $('Code - Build Ollama Payload').item.json; } catch (e) { try { review = $json; } catch (e2) {} }
sd.counts.analyses_done += 1;
return [{ json: {
  review_key: String(review.review_key || ''),
  sentiment: sentiment,
  issues: JSON.stringify(issues),
  summary: summary,
  urgency: urgency,
  analysis_status: 'done'
}, pairedItem: { item: 0 } }];
"""

S_MARK_FAILED = r"""
function errMsg(e) {
  if (e === undefined || e === null || e === '') return 'unknown error';
  if (typeof e === 'string') return e;
  if (typeof e === 'object') {
    if (typeof e.message === 'string' && e.message) return e.message;
    try { return JSON.stringify(e); } catch (err) { return String(e); }
  }
  return String(e);
}
const sd = $getWorkflowStaticData('global');
let review = {};
try { review = $('Code - Build Ollama Payload').item.json; } catch (e) {
  try { review = $('Loop Over Analysis Items').item.json; } catch (e2) { review = $json || {}; }
}
const msg = errMsg($json && $json.error).slice(0, 300);
sd.counts.analyses_failed += 1;
sd.run_errors.push({ scope: 'analysis', key: String(review.review_key || ''), message: msg });
return [{ json: {
  review_key: String(review.review_key || ''),
  sentiment: '',
  issues: '',
  summary: '',
  urgency: '',
  analysis_status: 'failed'
}, pairedItem: { item: 0 } }];
"""

S_LOG_ANALYSIS_ERROR = r"""
function errMsg(e) {
  if (e === undefined || e === null || e === '') return 'unknown error';
  if (typeof e === 'string') return e;
  if (typeof e === 'object') {
    if (typeof e.message === 'string' && e.message) return e.message;
    try { return JSON.stringify(e); } catch (err) { return String(e); }
  }
  return String(e);
}
const sd = $getWorkflowStaticData('global');
const msg = errMsg($json && $json.error).slice(0, 300);
sd.run_errors.push({ scope: 'sheets', key: String(($json && $json.review_key) || 'update_analysis'), message: msg });
return [{ json: { _note: 'analysis update failed', error: msg }, pairedItem: { item: 0 } }];
"""

S_PRODUCT_ERROR = r"""
function errMsg(e) {
  if (e === undefined || e === null || e === '') return 'unknown error';
  if (typeof e === 'string') return e;
  if (typeof e === 'object') {
    if (typeof e.message === 'string' && e.message) return e.message;
    try { return JSON.stringify(e); } catch (err) { return String(e); }
  }
  return String(e);
}
const sd = $getWorkflowStaticData('global');
let product = {};
try { product = $('Loop Over Products').item.json; } catch (e) { product = $json || {}; }
const msg = errMsg($json && $json.error).slice(0, 500);
const shop_id = String(product.shop_id || '');
const item_id = String(product.item_id || '');
sd.run_errors.push({ scope: 'product', key: shop_id + '_' + item_id, message: msg });
if (shop_id && item_id) {
  sd.productChecks = (sd.productChecks || []).filter(function (c) {
    return String(c.shop_id) + '_' + String(c.item_id) !== shop_id + '_' + item_id;
  });
  sd.productChecks.push({
    shop_id: shop_id,
    item_id: item_id,
    product_name: product.product_name || '',
    last_review_check: new Date().toISOString(),
    status: 'error'
  });
}
return [{ json: { shop_id: shop_id, item_id: item_id, status: 'error', error_message: msg }, pairedItem: { item: 0 } }];
"""

S_BUILD_CHECKS = r"""
const sd = $getWorkflowStaticData('global');
const checks = sd.productChecks || [];
const out = [];
for (let i = 0; i < checks.length; i++) {
  const c = checks[i];
  if (!c.shop_id || !c.item_id) continue;
  out.push({ json: {
    shop_id: String(c.shop_id),
    item_id: String(c.item_id),
    last_review_check: c.last_review_check || new Date().toISOString(),
    status: c.status || 'ok'
  }, pairedItem: { item: 0 } });
}
if (out.length === 0) return [{ json: { _marker: 'no_checks' }, pairedItem: { item: 0 } }];
return out;
"""

S_BUILD_SHOP_STATUS = r"""
const sd = $getWorkflowStaticData('global');
const shops = sd.shops || [];
const last = {};
const order = [];
for (let i = 0; i < shops.length; i++) {
  const s = shops[i];
  const k = String(s.shop_id || '');
  if (!k) continue;
  if (!last[k]) order.push(k);
  last[k] = s;
}
if (order.length === 0) return [{ json: { _marker: 'no_shops' }, pairedItem: { item: 0 } }];
return order.map(function (k) {
  const s = last[k];
  return { json: {
    shop_id: k,
    last_checked_at: s.last_checked_at || new Date().toISOString(),
    status: s.status || 'ok',
    error_message: String(s.error_message || '').slice(0, 500)
  }, pairedItem: { item: 0 } };
});
"""

S_BUILD_RUN_LOG = r"""
const sd = $getWorkflowStaticData('global');
const c = sd.counts || {};
const shops = sd.shops || [];
let ok = 0, failed = 0;
for (let i = 0; i < shops.length; i++) {
  if (String(shops[i].status) === 'error') failed++;
  else ok++;
}
const errors = (sd.run_errors || []).slice(0, 20).map(function (e) {
  return e.scope + ':' + e.key + ' - ' + e.message;
});
return [{ json: {
  run_started_at: sd.run_started_at || '',
  run_finished_at: new Date().toISOString(),
  shops_total: shops.length,
  shops_ok: ok,
  shops_failed: failed,
  products_discovered: Number(c.products) || 0,
  reviews_new: Number(c.reviews_new) || 0,
  analyses_done: Number(c.analyses_done) || 0,
  analyses_failed: Number(c.analyses_failed) || 0,
  errors: errors.join(' | ').slice(0, 4000)
}, pairedItem: { item: 0 } }];
"""

# ===================== BUILD HELPERS =====================

NODES = []
CONN = {}

def node(name, ntype, tv, pos, params, **kw):
    nid = ''.join(ch for ch in name if ch.isalnum())[:32].lower() or 'node'
    n = {"id": nid, "name": name, "type": ntype, "typeVersion": tv,
         "position": list(pos), "parameters": params}
    n.update(kw)
    NODES.append(n)
    return name

def connect(src, dst, out=0, inp=0):
    main = CONN.setdefault(src, {}).setdefault("main", [])
    while len(main) <= out:
        main.append([])
    main[out].append({"node": dst, "type": "main", "index": inp})

def code(name, js, pos, **kw):
    return node(name, "n8n-nodes-base.code", 2, pos,
                {"mode": "runOnceForAllItems", "jsCode": js.strip("\n")}, **kw)

def if_node(name, left_value, right_value, pos):
    return node(name, "n8n-nodes-base.if", 2.3, pos, {
        "conditions": {
            "options": {"caseSensitive": False, "leftValue": "", "typeValidation": "strict", "version": 2},
            "conditions": [{
                "id": "c_" + ''.join(ch for ch in name if ch.isalnum()).lower()[:20],
                "leftValue": left_value,
                "rightValue": right_value,
                "operator": {"type": "string", "operation": "equals"},
            }],
            "combinator": "and",
        },
        "options": {},
    })

DOC_ID = "__FILL_SPREADSHEET_ID__"

def _doc():
    return {"__rl": True, "mode": "id", "value": DOC_ID, "cachedResultName": "Shopee Monitor"}

def _sheet(name):
    return {"__rl": True, "mode": "name", "value": name, "cachedResultName": name}

def sheets_read(name, sheet, pos, filters=None, fail_loud=False, **kw):
    params = {"resource": "sheet", "operation": "read",
              "documentId": _doc(), "sheetName": _sheet(sheet), "options": {}}
    if filters:
        params["filtersUI"] = {"values": [{"lookupColumn": c, "lookupValue": v} for c, v in filters]}
        params["combineFilters"] = "AND"
    kw.setdefault("alwaysOutputData", True)
    if not fail_loud:
        kw.setdefault("onError", "continueErrorOutput")
    kw.setdefault("retryOnFail", True)
    kw.setdefault("maxTries", 2)
    kw.setdefault("waitBetweenTries", 3000)
    return node(name, "n8n-nodes-base.googleSheets", 4.7, pos, params, **kw)

def _schema(cols):
    return [{"id": c, "displayName": c, "required": False, "defaultMatch": False,
             "display": True, "type": "string", "canBeUsedToMatch": True} for c in cols]

def _value_exprs(cols, overrides=None):
    overrides = overrides or {}
    return {c: overrides.get(c, "={{ $json." + c + " }}") for c in cols}

def sheets_write(name, operation, sheet, cols, pos, matching=None, overrides=None, **kw):
    columns = {"mappingMode": "defineBelow",
               "value": _value_exprs(cols, overrides),
               "schema": _schema(cols)}
    if matching:
        columns["matchingColumns"] = list(matching)
    params = {"resource": "sheet", "operation": operation,
              "documentId": _doc(), "sheetName": _sheet(sheet),
              "columns": columns, "options": {}}
    kw.setdefault("onError", "continueErrorOutput")
    kw.setdefault("retryOnFail", True)
    kw.setdefault("maxTries", 2)
    kw.setdefault("waitBetweenTries", 3000)
    return node(name, "n8n-nodes-base.googleSheets", 4.7, pos, params, **kw)

def http(name, method, url, pos, body=None, query=None, timeout=30000, **kw):
    params = {"method": method, "url": url, "options": {"timeout": timeout}}
    if query:
        params["sendQuery"] = True
        params["queryParameters"] = {"parameters": [{"name": k, "value": v} for k, v in query]}
    if body is not None:
        params["sendBody"] = True
        params["specifyBody"] = "json"
        params["jsonBody"] = body
    kw.setdefault("onError", "continueErrorOutput")
    kw.setdefault("retryOnFail", True)
    kw.setdefault("maxTries", 3)
    kw.setdefault("waitBetweenTries", 5000)
    return node(name, "n8n-nodes-base.httpRequest", 4.5, pos, params, **kw)

def loop(name, pos):
    return node(name, "n8n-nodes-base.splitInBatches", 3, pos,
                {"batchSize": 1, "options": {}})

# ===================== COLUMNS =====================

PRODUCT_COLS = ["shop_id", "shop_name", "item_id", "product_name", "product_url", "last_review_check", "status"]
REVIEW_COLS = ["review_key", "shop_id", "shop_name", "item_id", "product_name", "comment_id", "rating_star",
               "comment", "review_time", "collected_at", "sentiment", "issues", "summary", "urgency", "analysis_status"]
ANALYSIS_COLS = ["review_key", "sentiment", "issues", "summary", "urgency", "analysis_status"]
SHOP_STATUS_COLS = ["shop_id", "last_checked_at", "status", "error_message"]
PRODUCT_CHECK_COLS = ["shop_id", "item_id", "last_review_check", "status"]
RUNLOG_COLS = ["run_started_at", "run_finished_at", "shops_total", "shops_ok", "shops_failed",
               "products_discovered", "reviews_new", "analyses_done", "analyses_failed", "errors"]

# ===================== NODES =====================

node("Manual Trigger", "n8n-nodes-base.manualTrigger", 1, [0, 300], {})

node("Schedule Trigger", "n8n-nodes-base.scheduleTrigger", 1.2, [0, 120],
     {"rule": {"interval": [{"field": "hours", "hoursInterval": 6}]}},
     disabled=True)

node("Config", "n8n-nodes-base.set", 3.5, [220, 300], {
    "assignments": {"assignments": [
        {"id": "a01", "name": "DATA_SOURCE", "value": "import", "type": "string"},
        {"id": "a02", "name": "OLLAMA_ENABLED", "value": True, "type": "boolean"},
        {"id": "a03", "name": "OLLAMA_URL", "value": "http://172.24.0.1:11434/api/chat", "type": "string"},
        {"id": "a04", "name": "OLLAMA_MODEL", "value": "qwen2.5-coder:1.5b", "type": "string"},
        {"id": "a05", "name": "MAX_SHOPS", "value": 10, "type": "number"},
        {"id": "a06", "name": "MAX_PRODUCTS_PER_SHOP", "value": 20, "type": "number"},
        {"id": "a07", "name": "MAX_REVIEWS_PER_PRODUCT", "value": 50, "type": "number"},
        {"id": "a08", "name": "MAX_REVIEW_PAGES", "value": 3, "type": "number"},
        {"id": "a09", "name": "REVIEW_PAGE_SIZE", "value": 20, "type": "number"},
        {"id": "a10", "name": "MAX_AI_PER_PRODUCT", "value": 10, "type": "number"},
        {"id": "a11", "name": "REQUEST_DELAY_MS", "value": 1000, "type": "number"},
        {"id": "a12", "name": "AI_DELAY_MS", "value": 500, "type": "number"},
        {"id": "a13", "name": "SHOPEE_API_HOST", "value": "https://partner.shopeemobile.com", "type": "string"},
        {"id": "a14", "name": "SHOPEE_PARTNER_ID", "value": "", "type": "string"},
        {"id": "a15", "name": "SHOPEE_ACCESS_TOKEN", "value": "", "type": "string"},
        {"id": "a16", "name": "SHOPEE_PARTNER_KEY", "value": "", "type": "string"},
    ]},
    "options": {},
})

code("Init Run Stats", S_INIT, [440, 300])

sheets_read("Google Sheets - Read Shops", "ShopList", [660, 300], fail_loud=True)

code("Code - Filter Enabled Shops", S_FILTER_SHOPS, [880, 300])

loop("Loop Over Shops", [1100, 300])

if_node("IF - Product Source", "={{ $('Config').first().json.DATA_SOURCE }}", "open_api", [1320, 200])

code("Code - Build Product Sign", S_BUILD_PRODUCT_SIGN, [1540, 80],
     onError="continueErrorOutput")

http("HTTP - Shopee Get Item List", "GET",
     "={{ $('Config').first().json.SHOPEE_API_HOST + '/api/v2/product/get_item_list' }}",
     [1760, 80],
     query=[("partner_id", "={{ $json._partner_id }}"),
            ("timestamp", "={{ String($json._timestamp) }}"),
            ("shop_id", "={{ $json._shop_id }}"),
            ("access_token", "={{ $json._access_token }}"),
            ("sign", "={{ $json._sign }}"),
            ("offset", "0"),
            ("page_size", "={{ String(Math.min(Number($('Config').first().json.MAX_PRODUCTS_PER_SHOP || 20), 100)) }}")])

code("Code - Map API Products", S_MAP_API_PRODUCTS, [1980, 80])

sheets_read("Google Sheets - Read Product Imports", "ProductImports", [1540, 300],
            filters=[("shop_id", "={{ $('Loop Over Shops').item.json.shop_id }}")])

code("Code - Normalize Products", S_NORMALIZE_PRODUCTS, [2200, 300])

code("Code - Shop Error", S_SHOP_ERROR, [1760, 480])

code("Code - Collect Discovered Products", S_COLLECT_PRODUCTS, [2420, 300])

if_node("IF - Any Products", "={{ ($json.item_id !== undefined && String($json.item_id) !== '') ? 'yes' : 'no' }}",
        "yes", [2640, 300])

sheets_write("Google Sheets - Upsert Products", "appendOrUpdate", "Products", PRODUCT_COLS,
             [2860, 220], matching=["shop_id", "item_id"])

loop("Loop Over Products", [3080, 220])

code("Code - Throttle", S_THROTTLE, [3300, 220])

sheets_read("Google Sheets - Read Product Reviews", "Reviews", [3520, 220],
            filters=[("shop_id", "={{ $json.shop_id }}"), ("item_id", "={{ $json.item_id }}")])

code("Code - Build Product State", S_BUILD_STATE, [3740, 220])

if_node("IF - Review Source", "={{ $('Config').first().json.DATA_SOURCE }}", "open_api", [3960, 140])

sheets_read("Google Sheets - Read Review Imports", "ReviewImports", [4180, 40],
            filters=[("shop_id", "={{ $json.shop_id }}"), ("item_id", "={{ $json.item_id }}")])

code("Code - Init Review Fetch", S_INIT_FETCH, [4180, 240])

code("Code - Build Review Sign", S_REVIEW_SIGN, [4400, 240])

http("HTTP - Shopee Get Comments", "GET",
     "={{ $('Config').first().json.SHOPEE_API_HOST + '/api/v2/product/get_comment' }}",
     [4620, 240],
     query=[("partner_id", "={{ $json._partner_id }}"),
            ("timestamp", "={{ String($json._timestamp) }}"),
            ("shop_id", "={{ $json._shop_id }}"),
            ("access_token", "={{ $json._access_token }}"),
            ("sign", "={{ $json._sign }}"),
            ("item_id", "={{ $json.item_id }}"),
            ("comment_id", "={{ String($json._cursor) }}"),
            ("page_size", "={{ String($('Config').first().json.REVIEW_PAGE_SIZE || 20) }}")])

code("Code - Parse Comments Page", S_PARSE_COMMENTS, [4840, 240])

if_node("IF - More Review Pages", "={{ $json._more }}", "yes", [5060, 240])

code("Code - Collect API Reviews", S_COLLECT_API, [5280, 140])

code("Code - Normalize Reviews", S_NORMALIZE_REVIEWS, [4400, 460])

code("Code - Deduplicate Reviews", S_DEDUP_REVIEWS, [4620, 460])

if_node("IF - New Reviews", "={{ ($json.review_key !== undefined && $json.review_key !== '') ? 'yes' : 'no' }}",
        "yes", [4840, 460])

sheets_write("Google Sheets - Save Reviews", "append", "Reviews", REVIEW_COLS, [5060, 460])

code("Code - Build Analysis Queue", S_BUILD_QUEUE, [5280, 460])

if_node("IF - Analysis Needed",
        "={{ ($json.review_key !== undefined && $json.review_key !== '' && $('Config').first().json.OLLAMA_ENABLED === true) ? 'yes' : 'no' }}",
        "yes", [5500, 340])

loop("Loop Over Analysis Items", [5720, 340])

code("Code - Throttle AI", S_THROTTLE.replace("REQUEST_DELAY_MS", "AI_DELAY_MS"), [5940, 340])

code("Code - Build Ollama Payload", S_PAYLOAD, [6160, 340])

http("HTTP - Ollama Chat", "POST", "={{ $('Config').first().json.OLLAMA_URL }}", [6380, 340],
     body="={{ JSON.stringify($json.payload) }}", timeout=120000)

code("Code - Parse Analysis", S_PARSE_ANALYSIS, [6600, 260])

code("Code - Mark Analysis Failed", S_MARK_FAILED, [6600, 480])

sheets_write("Google Sheets - Update Analysis", "update", "Reviews", ANALYSIS_COLS, [6820, 340],
             matching=["review_key"])

code("Code - Log Analysis Error", S_LOG_ANALYSIS_ERROR, [7040, 520])

code("Code - Build Product Checks", S_BUILD_CHECKS, [5940, 640])

sheets_write("Google Sheets - Update Product Check", "update", "Products", PRODUCT_CHECK_COLS, [6160, 640],
             matching=["shop_id", "item_id"])

code("Code - Build Shop Status Rows", S_BUILD_SHOP_STATUS, [6380, 760])

sheets_write("Google Sheets - Update Shop Status", "update", "ShopList", SHOP_STATUS_COLS, [6600, 760],
             matching=["shop_id"])

code("Code - Build Run Log", S_BUILD_RUN_LOG, [6820, 760])

sheets_write("Google Sheets - Save Run Log", "append", "RunLog", RUNLOG_COLS, [7040, 760])

code("Code - Product Error", S_PRODUCT_ERROR, [3520, 700])

# ===================== CONNECTIONS =====================

connect("Manual Trigger", "Config")
connect("Schedule Trigger", "Config")
connect("Config", "Init Run Stats")
connect("Init Run Stats", "Google Sheets - Read Shops")
connect("Google Sheets - Read Shops", "Code - Filter Enabled Shops")
connect("Code - Filter Enabled Shops", "Loop Over Shops")

# --- shop loop body (discovery) ---
connect("Loop Over Shops", "IF - Product Source", out=1)          # loop output
connect("IF - Product Source", "Code - Build Product Sign", out=0)   # open_api = true
connect("IF - Product Source", "Google Sheets - Read Product Imports", out=1)  # import = false
connect("Code - Build Product Sign", "HTTP - Shopee Get Item List")
connect("HTTP - Shopee Get Item List", "Code - Map API Products", out=0)
connect("HTTP - Shopee Get Item List", "Code - Shop Error", out=1)
connect("Code - Map API Products", "Code - Normalize Products", out=0)
connect("Code - Map API Products", "Code - Shop Error", out=1)
connect("Google Sheets - Read Product Imports", "Code - Normalize Products", out=0)
connect("Google Sheets - Read Product Imports", "Code - Shop Error", out=1)
connect("Code - Build Product Sign", "Code - Shop Error", out=1)
connect("Code - Normalize Products", "Code - Shop Error", out=1)
connect("Code - Normalize Products", "Loop Over Shops", out=0)
connect("Code - Shop Error", "Loop Over Shops")

# --- after shop loop ---
connect("Loop Over Shops", "Code - Collect Discovered Products", out=0)   # done
connect("Code - Collect Discovered Products", "IF - Any Products")
connect("IF - Any Products", "Google Sheets - Upsert Products", out=0)   # yes
connect("IF - Any Products", "Code - Build Shop Status Rows", out=1)     # no products -> finalize
connect("Google Sheets - Upsert Products", "Loop Over Products", out=0)
connect("Google Sheets - Upsert Products", "Code - Build Shop Status Rows", out=1)  # upsert error -> finalize

# --- product loop body (reviews) ---
connect("Loop Over Products", "Code - Throttle", out=1)   # loop output
connect("Code - Throttle", "Google Sheets - Read Product Reviews", out=0)
connect("Code - Throttle", "Code - Product Error", out=1)
connect("Google Sheets - Read Product Reviews", "Code - Build Product State", out=0)
connect("Google Sheets - Read Product Reviews", "Code - Product Error", out=1)
connect("Code - Build Product State", "IF - Review Source")
connect("IF - Review Source", "Google Sheets - Read Review Imports", out=1)  # import = false
connect("IF - Review Source", "Code - Init Review Fetch", out=0)             # open_api = true
connect("Google Sheets - Read Review Imports", "Code - Normalize Reviews", out=0)
connect("Google Sheets - Read Review Imports", "Code - Product Error", out=1)
connect("Code - Init Review Fetch", "Code - Build Review Sign")
connect("Code - Build Review Sign", "HTTP - Shopee Get Comments")
connect("HTTP - Shopee Get Comments", "Code - Parse Comments Page", out=0)
connect("HTTP - Shopee Get Comments", "Code - Product Error", out=1)
connect("Code - Parse Comments Page", "IF - More Review Pages", out=0)
connect("Code - Parse Comments Page", "Code - Product Error", out=1)
connect("IF - More Review Pages", "Code - Build Review Sign", out=0)   # pagination cycle
connect("IF - More Review Pages", "Code - Collect API Reviews", out=1) # done
connect("Code - Collect API Reviews", "Code - Normalize Reviews")
connect("Code - Normalize Reviews", "Code - Deduplicate Reviews", out=0)
connect("Code - Normalize Reviews", "Code - Product Error", out=1)
connect("Code - Deduplicate Reviews", "IF - New Reviews", out=0)
connect("Code - Deduplicate Reviews", "Code - Product Error", out=1)
connect("IF - New Reviews", "Google Sheets - Save Reviews", out=0)   # yes
connect("IF - New Reviews", "Code - Build Analysis Queue", out=1)    # no
connect("Google Sheets - Save Reviews", "Code - Build Analysis Queue", out=0)
connect("Google Sheets - Save Reviews", "Code - Product Error", out=1)
connect("Code - Build Analysis Queue", "Loop Over Products")         # chain end -> next product
connect("Code - Product Error", "Loop Over Products")

# --- analysis loop (chạy tuần tự SAU product loop) ---
connect("Loop Over Products", "IF - Analysis Needed", out=0)          # done
connect("IF - Analysis Needed", "Loop Over Analysis Items", out=0)    # yes
connect("IF - Analysis Needed", "Code - Build Product Checks", out=1) # no
connect("Loop Over Analysis Items", "Code - Throttle AI", out=1)
connect("Code - Throttle AI", "Code - Build Ollama Payload", out=0)
connect("Code - Throttle AI", "Code - Mark Analysis Failed", out=1)
connect("Code - Build Ollama Payload", "HTTP - Ollama Chat", out=0)
connect("Code - Build Ollama Payload", "Code - Mark Analysis Failed", out=1)
connect("HTTP - Ollama Chat", "Code - Parse Analysis", out=0)
connect("HTTP - Ollama Chat", "Code - Mark Analysis Failed", out=1)
connect("Code - Parse Analysis", "Google Sheets - Update Analysis", out=0)
connect("Code - Parse Analysis", "Code - Mark Analysis Failed", out=1)
connect("Code - Mark Analysis Failed", "Google Sheets - Update Analysis", out=0)
connect("Google Sheets - Update Analysis", "Loop Over Analysis Items", out=0)
connect("Google Sheets - Update Analysis", "Code - Log Analysis Error", out=1)
connect("Code - Log Analysis Error", "Loop Over Analysis Items", out=0)
connect("Loop Over Analysis Items", "Code - Build Product Checks", out=0)  # done

# --- error routing trong product body (thêm) ---
connect("Code - Build Review Sign", "Code - Product Error", out=1)
connect("Code - Build Product State", "Code - Product Error", out=1)
connect("Code - Init Review Fetch", "Code - Product Error", out=1)

# --- finalize ---
connect("Code - Build Product Checks", "Google Sheets - Update Product Check", out=0)
connect("Google Sheets - Update Product Check", "Code - Build Shop Status Rows", out=0)
connect("Google Sheets - Update Product Check", "Code - Build Shop Status Rows", out=1)
connect("Code - Build Shop Status Rows", "Google Sheets - Update Shop Status", out=0)
connect("Google Sheets - Update Shop Status", "Code - Build Run Log", out=0)
connect("Google Sheets - Update Shop Status", "Code - Build Run Log", out=1)
connect("Code - Build Run Log", "Google Sheets - Save Run Log", out=0)

# ===================== ONERROR CHO CÁC CODE NODE CÓ KẾT NỐI ERROR =====================

ONERROR_NODES = {
    "Code - Map API Products", "Code - Normalize Products", "Code - Throttle", "Code - Throttle AI",
    "Code - Normalize Reviews", "Code - Deduplicate Reviews", "Code - Build Analysis Queue",
    "Code - Build Ollama Payload", "Code - Parse Analysis", "Code - Build Review Sign",
    "Code - Build Product State", "Code - Init Review Fetch",
}
for _n in NODES:
    if _n["name"] in ONERROR_NODES:
        _n["onError"] = "continueErrorOutput"

def emit(path, wf):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(wf, f, ensure_ascii=False, indent=2)
    print("wrote", path, "nodes:", len(wf["nodes"]))

MAIN_WF = {
    "id": "shopeereviewmonitor",
    "name": "Shopee Review Monitor",
    "nodes": NODES,
    "connections": CONN,
    "settings": {"executionOrder": "v1"},
    "active": False,
    "tags": [],
}
emit(os.path.join(OUT_DIR, "shopee-monitor-workflow.json"), MAIN_WF)

# ===================== MIRROR TEST VARIANT (Google Sheets -> Code fake) =====================

FIXTURES = {
    "shops": [
        {"shop_id": "111", "shop_name": "Shop Ánh Dương", "shop_url": "https://shopee.vn/shop.111", "enabled": "TRUE", "last_checked_at": "", "status": "", "error_message": ""},
        {"shop_id": "222", "shop_name": "Shop Bốn Mùa", "shop_url": "https://shopee.vn/shop.222", "enabled": "true", "last_checked_at": "", "status": "", "error_message": ""},
        {"shop_id": "333", "shop_name": "Shop Tắt (disabled)", "shop_url": "https://shopee.vn/shop.333", "enabled": "FALSE", "last_checked_at": "", "status": "", "error_message": ""},
    ],
    "product_imports": [
        {"shop_id": "111", "item_id": "501", "product_name": "Son môi Velvet Red"},
        {"shop_id": "111", "item_id": "502", "product_name": "Kem dưỡng ẩm Aloe"},
        {"shop_id": "111", "item_id": "501", "product_name": "Son môi Velvet Red (trung)"},
        {"shop_id": "222", "item_id": "601", "product_name": "Túi xách da mềm"},
    ],
    "review_imports": [
        {"shop_id": "111", "item_id": "501", "comment_id": "R1", "rating_star": 5, "comment": "San pham tot (dup cua seed)", "review_time": "2026-10-01T10:00:00.000Z"},
        {"shop_id": "111", "item_id": "501", "comment_id": "R2", "rating_star": 2, "comment": "Giao hang cham, hang bi loi son", "review_time": "1760000000"},
        {"shop_id": "111", "item_id": "501", "comment_id": "R2", "rating_star": 2, "comment": "Giao hang cham (trung trong batch)", "review_time": "1760000000"},
        {"shop_id": "111", "item_id": "501", "comment_id": "R3", "rating_star": 4, "comment": "Dep nhung mau chot hoi nhạt", "review_time": "01/10/2026 10:30"},
        {"shop_id": "111", "item_id": "502", "comment_id": "R10", "rating_star": 1, "comment": "Kem dich vu, khong giong mo ta", "review_time": "2026-10-02T08:00:00Z"},
        {"shop_id": "222", "item_id": "601", "comment_id": "R20", "rating_star": 5, "comment": "Tui dep, giao nhanh", "review_time": "2026-10-03"},
        {"shop_id": "222", "item_id": "601", "comment_id": "", "rating_star": 3, "comment": "Thieu comment_id se bi bo qua", "review_time": "2026-10-03"},
    ],
    "seed_reviews": [
        {"review_key": "111_501_R1", "shop_id": "111", "shop_name": "Shop Ánh Dương", "item_id": "501", "product_name": "Son môi Velvet Red", "comment_id": "R1", "rating_star": 5, "comment": "San pham rat tot", "review_time": "2026-09-30T00:00:00.000Z", "collected_at": "2026-10-01T00:00:00.000Z", "sentiment": "positive", "issues": "[]", "summary": "Khen sản phẩm", "urgency": "low", "analysis_status": "done"},
        {"review_key": "111_501_R9", "shop_id": "111", "shop_name": "Shop Ánh Dương", "item_id": "501", "product_name": "Son môi Velvet Red", "comment_id": "R9", "rating_star": 1, "comment": "Cham giao hang qua, dong goi cau tat", "review_time": "2026-09-30T01:00:00.000Z", "collected_at": "2026-10-01T00:00:00.000Z", "sentiment": "", "issues": "", "summary": "", "urgency": "", "analysis_status": "pending"},
    ],
}

SEED_JS = "\nconst _sd = $getWorkflowStaticData('global');\n_sd.fixtures = " + json.dumps(FIXTURES, ensure_ascii=False) + ";\n_sd.sheets = { Products: [], Reviews: JSON.parse(JSON.stringify(_sd.fixtures.seed_reviews)), RunLog: [] };\n"

def fake_code(js, keep_on_error=True, retry=False):
    p = {"mode": "runOnceForAllItems", "jsCode": js.strip("\n")}
    kw = {}
    if keep_on_error:
        kw["onError"] = "continueErrorOutput"
    return {"type": "n8n-nodes-base.code", "typeVersion": 2, "parameters": p, **kw}

def _mapped(cols, paired="idx"):
    return cols

FAKES = {}

FAKES["Google Sheets - Read Shops"] = fake_code(
    "const sd = $getWorkflowStaticData('global');\n"
    "return (sd.fixtures.shops || []).map(function (r) { return { json: r, pairedItem: { item: 0 } }; });")

FAKES["Google Sheets - Read Product Imports"] = fake_code(
    "const sd = $getWorkflowStaticData('global');\n"
    "let shopId = '';\n"
    "try { shopId = $('Loop Over Shops').item.json.shop_id; } catch (e) {}\n"
    "const rows = (sd.fixtures.product_imports || []).filter(function (r) { return String(r.shop_id) === String(shopId); });\n"
    "if (!rows.length) return [{ json: {} }];\n"
    "return rows.map(function (r) { return { json: r, pairedItem: { item: 0 } }; });")

FAKES["Google Sheets - Upsert Products"] = fake_code(
    "const sd = $getWorkflowStaticData('global');\n"
    "sd.sheets.Products = sd.sheets.Products || [];\n"
    "const cols = " + json.dumps(PRODUCT_COLS) + ";\n"
    "const input = $input.all();\n"
    "input.forEach(function (item) {\n"
    "  const r = item.json;\n"
    "  let found = -1;\n"
    "  for (let i = 0; i < sd.sheets.Products.length; i++) {\n"
    "    const p = sd.sheets.Products[i];\n"
    "    if (String(p.shop_id) === String(r.shop_id) && String(p.item_id) === String(r.item_id)) { found = i; break; }\n"
    "  }\n"
    "  const row = {};\n"
    "  cols.forEach(function (c) { row[c] = r[c] !== undefined ? r[c] : ''; });\n"
    "  if (found >= 0) sd.sheets.Products[found] = Object.assign(sd.sheets.Products[found], row);\n"
    "  else sd.sheets.Products.push(row);\n"
    "});\n"
    "return input.map(function (item, idx) {\n"
    "  const jsonOut = {};\n"
    "  cols.forEach(function (c) { jsonOut[c] = item.json[c] !== undefined ? item.json[c] : ''; });\n"
    "  return { json: jsonOut, pairedItem: { item: idx } };\n"
    "});")

FAKES["Google Sheets - Read Product Reviews"] = fake_code(
    "const sd = $getWorkflowStaticData('global');\n"
    "const rows = (sd.sheets.Reviews || []).filter(function (r) {\n"
    "  return String(r.shop_id) === String($json.shop_id) && String(r.item_id) === String($json.item_id);\n"
    "});\n"
    "if (!rows.length) return [{ json: {} }];\n"
    "return rows.map(function (r) { return { json: r, pairedItem: { item: 0 } }; });")

FAKES["Google Sheets - Read Review Imports"] = fake_code(
    "const sd = $getWorkflowStaticData('global');\n"
    "const rows = (sd.fixtures.review_imports || []).filter(function (r) {\n"
    "  return String(r.shop_id) === String($json.shop_id) && String(r.item_id) === String($json.item_id);\n"
    "});\n"
    "if (!rows.length) return [{ json: {} }];\n"
    "return rows.map(function (r) { return { json: r, pairedItem: { item: 0 } }; });")

FAKES["Google Sheets - Save Reviews"] = fake_code(
    "const sd = $getWorkflowStaticData('global');\n"
    "sd.sheets.Reviews = sd.sheets.Reviews || [];\n"
    "const cols = " + json.dumps(REVIEW_COLS) + ";\n"
    "const input = $input.all();\n"
    "input.forEach(function (item) {\n"
    "  const row = {};\n"
    "  cols.forEach(function (c) { row[c] = item.json[c] !== undefined ? item.json[c] : ''; });\n"
    "  sd.sheets.Reviews.push(row);\n"
    "});\n"
    "return input.map(function (item, idx) {\n"
    "  const jsonOut = {};\n"
    "  cols.forEach(function (c) { jsonOut[c] = item.json[c] !== undefined ? item.json[c] : ''; });\n"
    "  return { json: jsonOut, pairedItem: { item: idx } };\n"
    "});")

FAKES["Google Sheets - Update Analysis"] = fake_code(
    "const sd = $getWorkflowStaticData('global');\n"
    "sd.sheets.Reviews = sd.sheets.Reviews || [];\n"
    "const cols = " + json.dumps(ANALYSIS_COLS) + ";\n"
    "const input = $input.all();\n"
    "input.forEach(function (item) {\n"
    "  const r = item.json;\n"
    "  for (let i = 0; i < sd.sheets.Reviews.length; i++) {\n"
    "    if (String(sd.sheets.Reviews[i].review_key) === String(r.review_key)) {\n"
    "      cols.forEach(function (c) { sd.sheets.Reviews[i][c] = r[c] !== undefined ? r[c] : ''; });\n"
    "      break;\n"
    "    }\n"
    "  }\n"
    "});\n"
    "return input.map(function (item, idx) {\n"
    "  const jsonOut = {};\n"
    "  cols.forEach(function (c) { jsonOut[c] = item.json[c] !== undefined ? item.json[c] : ''; });\n"
    "  return { json: jsonOut, pairedItem: { item: idx } };\n"
    "});")

FAKES["Google Sheets - Update Product Check"] = fake_code(
    "const sd = $getWorkflowStaticData('global');\n"
    "sd.sheets.Products = sd.sheets.Products || [];\n"
    "const cols = " + json.dumps(PRODUCT_CHECK_COLS) + ";\n"
    "const input = $input.all();\n"
    "input.forEach(function (item) {\n"
    "  const r = item.json;\n"
    "  for (let i = 0; i < sd.sheets.Products.length; i++) {\n"
    "    const p = sd.sheets.Products[i];\n"
    "    if (String(p.shop_id) === String(r.shop_id) && String(p.item_id) === String(r.item_id)) {\n"
    "      cols.forEach(function (c) { p[c] = r[c] !== undefined ? r[c] : ''; });\n"
    "      break;\n"
    "    }\n"
    "  }\n"
    "});\n"
    "return input.map(function (item, idx) {\n"
    "  const jsonOut = {};\n"
    "  cols.forEach(function (c) { jsonOut[c] = item.json[c] !== undefined ? item.json[c] : ''; });\n"
    "  return { json: jsonOut, pairedItem: { item: idx } };\n"
    "});")

FAKES["Google Sheets - Update Shop Status"] = fake_code(
    "const sd = $getWorkflowStaticData('global');\n"
    "const cols = " + json.dumps(SHOP_STATUS_COLS) + ";\n"
    "const input = $input.all();\n"
    "input.forEach(function (item) {\n"
    "  const r = item.json;\n"
    "  for (let i = 0; i < (sd.fixtures.shops || []).length; i++) {\n"
    "    if (String(sd.fixtures.shops[i].shop_id) === String(r.shop_id)) {\n"
    "      cols.forEach(function (c) { sd.fixtures.shops[i][c] = r[c] !== undefined ? r[c] : ''; });\n"
    "      break;\n"
    "    }\n"
    "  }\n"
    "});\n"
    "return input.map(function (item, idx) {\n"
    "  const jsonOut = {};\n"
    "  cols.forEach(function (c) { jsonOut[c] = item.json[c] !== undefined ? item.json[c] : ''; });\n"
    "  return { json: jsonOut, pairedItem: { item: idx } };\n"
    "});")

FAKES["Google Sheets - Save Run Log"] = fake_code(
    "const sd = $getWorkflowStaticData('global');\n"
    "const cols = " + json.dumps(RUNLOG_COLS) + ";\n"
    "const row = {};\n"
    "cols.forEach(function (c) { row[c] = $json[c] !== undefined ? $json[c] : ''; });\n"
    "sd.sheets.RunLog.push(row);\n"
    "const out = Object.assign({}, row, {\n"
    "  __debug_products: JSON.stringify(sd.sheets.Products),\n"
    "  __debug_reviews: JSON.stringify(sd.sheets.Reviews),\n"
    "  __debug_shops: JSON.stringify(sd.fixtures.shops),\n"
    "});\n"
    "return [{ json: out, pairedItem: { item: 0 } }];")

# ---- Build mirror workflow ----

MIRROR = copy.deepcopy(MAIN_WF)
MIRROR["id"] = "shopeereviewmirror1"
MIRROR["name"] = "Shopee Review Monitor [MIRROR TEST - Sheets faked]"

for n in MIRROR["nodes"]:
    name = n["name"]
    if name in FAKES:
        fake = FAKES[name]
        n["type"] = fake["type"]
        n["typeVersion"] = fake["typeVersion"]
        n["parameters"] = fake["parameters"]
        if "onError" in fake:
            n["onError"] = fake["onError"]
        n.pop("retryOnFail", None)
        n.pop("maxTries", None)
        n.pop("waitBetweenTries", None)
        n.pop("alwaysOutputData", None)
    if name == "Init Run Stats":
        n["parameters"]["jsCode"] = SEED_JS + "\n" + n["parameters"]["jsCode"]
    if name == "Config":
        for a in n["parameters"]["assignments"]["assignments"]:
            if a["name"] in ("REQUEST_DELAY_MS", "AI_DELAY_MS"):
                a["value"] = 100

emit(os.path.join(OUT_DIR, "shopee-monitor-mirror-test.json"), MIRROR)
print("mirror fakes applied:", len([n for n in MIRROR['nodes'] if n['type'] == 'n8n-nodes-base.code']))















