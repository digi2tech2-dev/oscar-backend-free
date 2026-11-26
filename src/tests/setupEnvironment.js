'use strict';

// Tests use reserved example domains only. The supplier allowlist is always
// enforced, including under NODE_ENV=test, so test execution cannot mask a
// missing production trust configuration.
process.env.TRUSTED_PROVIDER_HOSTS = [
    'torosfon.example.com',
    'alkasr.example.com',
    'royal.example.com',
    'x.example',
    'y.example',
    'api.example.com',
    'example.com',
    'mock.example.com',
    'supplier.example',
    'new.example',
].join(',');
