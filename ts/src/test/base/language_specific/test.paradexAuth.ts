// NO_AUTO_TRANSPILE
// @ts-nocheck

import assert from 'assert';
import ccxt from '../../../../ccxt.js';

// paradex sign-in flows that need real http status codes: the static fixtures mock fetch ()
// above handleErrors (), so the 401 handling is driven here through fetchImplementation

const systemConfig = {
    'starknet_chain_id': 'PRIVATE_SN_POTC_SEPOLIA',
    'l1_chain_id': '11155111',
    'paraclear_account_proxy_hash': '0x3530cc4759d78042f1b543bf797f5f3d647cde0388c33734cf91b7f7b9314a9',
    'paraclear_account_hash': '0x41cb0280ebadaa75f996d8d92c6f265f6d040bb3ba442e5f86a554f1765244e',
};

// test keys only: a stark key used as a subkey of the account below
const subkeyPrivateKey = '0x2f85a3afa49c9a88700f5dc72865146edba0bb5fcbdd6780a6be65d4c97a6fc';
const subkeyPublicKey = '0xc37d1af7d2f94365bd704eb35af1d7ce19bf9115d440a28d078bef26d65847';
const accountAddress = '0x51312b7c9101038d2e3a651b662a045a81ea2cc598d5a5ce3513b511115202';

function createExchange (replies, credentials = true) {
    const config = {
        'enableRateLimit': false,
        'options': {
            'systemConfig': systemConfig,
            'authToken': 'stale-token',
            'expires': 9999999999, // valid by the local clock, the server decides it is not
        },
    };
    if (credentials) {
        config['walletAddress'] = accountAddress;
        config['privateKey'] = subkeyPrivateKey;
    }
    const exchange = new ccxt.paradex (config);
    const calls = [];
    exchange.fetchImplementation = async (url, init) => {
        const headers = ((init !== undefined) && (init.headers !== undefined)) ? init.headers : {};
        calls.push ({ 'method': init.method, 'url': url.replace ('https://api.prod.paradex.trade', ''), 'authorization': headers['Authorization'] });
        const reply = replies.shift ();
        assert (reply !== undefined, 'unexpected request ' + init.method + ' ' + url);
        return new Response (JSON.stringify (reply[1]), { 'status': reply[0], 'headers': { 'Content-Type': 'application/json' }});
    };
    return [ exchange, calls ];
}

const invalidToken = [ 401, { 'error': 'INVALID_TOKEN', 'message': 'invalid bearer jwt' } ];

async function testRetriesOnceAfterRejectedToken () {
    const [ exchange, calls ] = createExchange ([
        invalidToken,
        [ 200, { 'jwt_token': 'fresh-token' } ],
        [ 200, { 'account': accountAddress } ],
    ]);
    const response = await exchange.privateGetAccount ();
    assert.strictEqual (response['account'], accountAddress);
    assert.deepStrictEqual (calls.map ((call) => call['method'] + ' ' + call['url']), [
        'GET /v1/account?',
        'POST /v1/auth/' + subkeyPublicKey,
        'GET /v1/account?',
    ]);
    assert.strictEqual (calls[0]['authorization'], 'Bearer stale-token');
    assert.strictEqual (calls[2]['authorization'], 'Bearer fresh-token');
    assert.strictEqual (exchange.options['authToken'], 'fresh-token');
}

async function testRevokedKeySurfacesWithoutLooping () {
    const [ exchange, calls ] = createExchange ([
        invalidToken,
        [ 401, { 'error': 'SUBKEY_REVOKED', 'message': 'subkey revoked' } ],
    ]);
    await assert.rejects (exchange.privateGetAccount (), (error) => (error instanceof ccxt.AuthenticationError) && error.message.includes ('key revoked or inactive'));
    assert.strictEqual (calls.length, 2);
}

async function testSecondRejectionIsNotRetried () {
    const [ exchange, calls ] = createExchange ([
        invalidToken,
        [ 200, { 'jwt_token': 'fresh-token' } ],
        invalidToken,
    ]);
    await assert.rejects (exchange.privateGetAccount (), ccxt.AuthenticationError);
    assert.strictEqual (calls.length, 3);
}

async function testLongLivedTokenWithoutKeysIsNotRetried () {
    const [ exchange, calls ] = createExchange ([ invalidToken ], false);
    delete exchange.options['expires'];
    exchange.options['authToken'] = 'api-token';
    await assert.rejects (exchange.privateGetAccount (), (error) => (error instanceof ccxt.AuthenticationError) && error.message.includes ('INVALID_TOKEN'));
    assert.strictEqual (calls.length, 1);
    assert.strictEqual (exchange.options['authToken'], undefined);
}

async function testConcurrentCallersShareOneSignIn () {
    const [ exchange, calls ] = createExchange ([
        [ 200, { 'jwt_token': 'fresh-token' } ],
        [ 200, { 'account': accountAddress } ],
        [ 200, { 'account': accountAddress } ],
        [ 200, { 'account': accountAddress } ],
    ]);
    exchange.options['expires'] = 0;
    await Promise.all ([ exchange.privateGetAccount (), exchange.privateGetAccount (), exchange.privateGetAccount () ]);
    const signIns = calls.filter ((call) => (call['url'].indexOf ('/v1/auth/') === 0));
    assert.strictEqual (signIns.length, 1);
    assert.strictEqual (exchange.options['authenticatingRest'], false);
}

async function testParadexAuth () {
    await testRetriesOnceAfterRejectedToken ();
    await testRevokedKeySurfacesWithoutLooping ();
    await testSecondRejectionIsNotRetried ();
    await testLongLivedTokenWithoutKeysIsNotRetried ();
    await testConcurrentCallersShareOneSignIn ();
}

export default testParadexAuth;
