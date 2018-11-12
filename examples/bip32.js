var pkcs11js = require("pkcs11js");
var sha256 = require("sha256");
var BN = require('bn.js');


var pkcs11 = new pkcs11js.PKCS11();


var lib = "/usr/safenet/lunaclient/lib/libCryptoki2_64.so"
//var lib = "/usr/safenet/lunaclient/lib/libcklog2.so"
var slot = 0;
var pin = "userpin"

var secp256k1_N = new BN("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);

function generateSeed(session) {
    var seedTemplate = [
        {type: pkcs11js.CKA_KEY_TYPE, value: pkcs11js.CKK_GENERIC_SECRET},
        {type: pkcs11js.CKA_TOKEN, value: false},
        {type: pkcs11js.CKA_DERIVE, value: true},
        {type: pkcs11js.CKA_PRIVATE, value: true},
        {type: pkcs11js.CKA_EXTRACTABLE, value: false},
        {type: pkcs11js.CKA_MODIFIABLE, value: false},
        {type: pkcs11js.CKA_VALUE_LEN, value: 32}
    ];

    return pkcs11.C_GenerateKey(session, { mechanism: pkcs11js.CKM_GENERIC_SECRET_KEY_GEN }, seedTemplate);
}

function deriveMaster(session, seed) {
    var publicKeyTemplate = [
                        { type: pkcs11js.CKA_TOKEN, value: false },
                        { type: pkcs11js.CKA_PRIVATE, value: true },
                        { type: pkcs11js.CKA_VERIFY, value: true },
                        { type: pkcs11js.CKA_DERIVE, value: true },
                        { type: pkcs11js.CKA_MODIFIABLE, value: false },
    ];
    var privateKeyTemplate = [
                        { type: pkcs11js.CKA_TOKEN, value: false },
                        { type: pkcs11js.CKA_PRIVATE, value: true },
                        { type: pkcs11js.CKA_SIGN, value: true },
                        { type: pkcs11js.CKA_DERIVE, value: true },
                        { type: pkcs11js.CKA_MODIFIABLE, value: false },
                        { type: pkcs11js.CKA_EXTRACTABLE, value: false },
    ];

    return pkcs11.DeriveBIP32Master(session, seed, publicKeyTemplate, privateKeyTemplate);
}

function deriveChild(session, masterPrivate, path) {
    var publicKeyTemplate = [
                        { type: pkcs11js.CKA_TOKEN, value: false },
                        { type: pkcs11js.CKA_PRIVATE, value: true },
                        { type: pkcs11js.CKA_VERIFY, value: true },
                        { type: pkcs11js.CKA_DERIVE, value: false },
                        { type: pkcs11js.CKA_MODIFIABLE, value: false },
    ];
    var privateKeyTemplate = [
                        { type: pkcs11js.CKA_TOKEN, value: false },
                        { type: pkcs11js.CKA_PRIVATE, value: true },
                        { type: pkcs11js.CKA_SIGN, value: true },
                        { type: pkcs11js.CKA_DERIVE, value: false },
                        { type: pkcs11js.CKA_MODIFIABLE, value: false },
                        { type: pkcs11js.CKA_EXTRACTABLE, value: false },
    ];

    return pkcs11.DeriveBIP32Child(session, masterPrivate, publicKeyTemplate, privateKeyTemplate, path);
}

function sign(session, privateKey, data) {
    var mech = {
        mechanism: pkcs11js.CKM_ECDSA,
    };
    pkcs11.C_SignInit(session, mech, privateKey)
    return pkcs11.C_Sign(session, data, Buffer.alloc(64));
}

function verify(session, publicKey, data, signature) {
    var mech = {
        mechanism: pkcs11js.CKM_ECDSA,
    };
    pkcs11.C_VerifyInit(session, mech, publicKey)
    return pkcs11.C_Verify(session, data, signature)
}

function signatureLowS(sig) {
    var r = new BN(sig.slice(0, sig.length / 2).toString('hex'), 16);
    var s = new BN(sig.slice(sig.length / 2).toString('hex'), 16);
    var halfOrder =  secp256k1_N.shrn(1);
    if (s.cmp(halfOrder) == 1) {
        s = secp256k1_N.sub(s);
    }
    return Buffer.concat([r.toBuffer("be", 32), s.toBuffer("be", 32)]);
}

pkcs11.load(lib);
pkcs11.C_Initialize();

try {

    var slots = pkcs11.C_GetSlotList(true);
    var slot = slots[slot];

    var session = pkcs11.C_OpenSession(slot, pkcs11js.CKF_RW_SESSION | pkcs11js.CKF_SERIAL_SESSION);

    pkcs11.C_Login(session, 1, pin);

    var seed = generateSeed(session);
    var master = deriveMaster(session, seed);
    var child = deriveChild(session, master['privateKey'], [0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0, 0]);

    var hash = sha256("BIP32 Message")
    var data = new Buffer(hash, "hex");

    var signature = sign(session, master['privateKey'], data);
    signature = signatureLowS(signature);
    verify(session, master['publicKey'], data, signature);

    pkcs11.C_Logout(session);
    pkcs11.C_CloseSession(session);
}
catch(e){
    console.error(e);
}
finally {
    pkcs11.C_Finalize();
}
