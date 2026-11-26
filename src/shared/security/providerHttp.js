'use strict';

const axios = require('axios');
const dns = require('node:dns');
const net = require('node:net');
const https = require('node:https');
const ipaddr = require('ipaddr.js');
const executionGate = require('./executionGate');

const parseTrustedHosts = (value = process.env.TRUSTED_PROVIDER_HOSTS || '') => new Set(
    value.split(',').map((host) => host.trim().toLowerCase().replace(/\.$/, '')).filter(Boolean)
);

const canonicalProviderUrl = (raw, trustedHosts = parseTrustedHosts()) => {
    if (typeof raw !== 'string' || raw.trim() !== raw || raw.length > 2048) {
        throw new Error('Provider destination is invalid');
    }
    let url;
    try { url = new URL(raw); } catch { throw new Error('Provider destination is invalid'); }
    if (url.username || url.password || url.hash) throw new Error('Provider destination is invalid');
    if (url.protocol !== 'https:') {
        throw new Error('Provider destination protocol is not allowed');
    }
    if (url.port && url.port !== '443') {
        throw new Error('Provider destination port is not allowed');
    }
    const hostname = url.hostname.toLowerCase().replace(/\.$/, '');
    if (!hostname || hostname.includes('%') || hostname === 'localhost' || hostname.endsWith('.localhost')) {
        throw new Error('Provider destination host is not allowed');
    }
    const testMode = process.env.NODE_ENV === 'test';
    if (!testMode && !trustedHosts.has(hostname)) throw new Error('Provider destination is not trusted');
    const ipLiteral = hostname.replace(/^\[|\]$/g, '');
    if (net.isIP(ipLiteral)) throw new Error('Provider destination must use an approved hostname');
    url.hostname = hostname;
    url.username = '';
    url.password = '';
    url.hash = '';
    return url;
};

const isProhibitedAddress = (address) => {
    if (!net.isIP(address)) return true;
    try {
        let parsed = ipaddr.parse(address);
        if (parsed.kind() === 'ipv6' && parsed.isIPv4MappedAddress()) parsed = parsed.toIPv4Address();
        return parsed.range() !== 'unicast';
    } catch { return true; }
};

const createPinnedLookup = (hostname, resolver = dns, trustedHosts = parseTrustedHosts()) =>
    (requestedHostname, options, callback) => {
        const cb = typeof options === 'function' ? options : callback;
        const opts = typeof options === 'object' ? options : {};
        if (requestedHostname.toLowerCase().replace(/\.$/, '') !== hostname) {
            return cb(new Error('Provider DNS name changed during request'));
        }
        resolver.lookup(hostname, { all: true, verbatim: true }, (err, records) => {
            if (err || !Array.isArray(records) || records.length === 0) return cb(new Error('Provider DNS resolution failed'));
            const addresses = records.map((record) => record.address);
            if (addresses.some(isProhibitedAddress)) return cb(new Error('Provider resolved to a prohibited network address'));
            // The socket connects to this validated answer directly. No second DNS lookup occurs.
            const selected = records[0];
            if (opts.all) return cb(null, records);
            return cb(null, selected.address, selected.family);
        });
    };

const createProviderHttpClient = (baseURL, headers, timeout = 15000) => {
    executionGate.assertEnabled('Supplier communication');
    const url = canonicalProviderUrl(baseURL);
    const agent = url.protocol === 'https:'
        ? new https.Agent({ keepAlive: false, rejectUnauthorized: true, lookup: createPinnedLookup(url.hostname) })
        : undefined;
    return axios.create({
        baseURL: url.toString(),
        timeout: Math.min(Math.max(Number(timeout) || 15000, 1000), 30000),
        maxRedirects: 0,
        maxContentLength: 2 * 1024 * 1024,
        maxBodyLength: 1024 * 1024,
        proxy: false,
        httpsAgent: agent,
        headers,
    });
};

module.exports = { canonicalProviderUrl, isProhibitedAddress, createPinnedLookup, createProviderHttpClient, parseTrustedHosts };
