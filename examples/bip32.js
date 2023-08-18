let pkcs11js = require("pkcs11js");
let sha256 = require("sha256");
let BN = require('bn.js');


let pkcs11 = new pkcs11js.PKCS11();


let lib = "/usr/safenet/lunaclient/lib/libCryptoki2_64.so"
let pin = "Wangsai123!"
let seedHandle = 55

let secp256k1_N = new BN("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);

function deriveMaster(session, seed) {
    let publicKeyTemplate = [
        { type: pkcs11js.CKA_TOKEN, value: false },
        { type: pkcs11js.CKA_PRIVATE, value: true },
        { type: pkcs11js.CKA_VERIFY, value: true },
        { type: pkcs11js.CKA_DERIVE, value: true },
        { type: pkcs11js.CKA_MODIFIABLE, value: false },
    ];
    let privateKeyTemplate = [
        { type: pkcs11js.CKA_TOKEN, value: true },
        { type: pkcs11js.CKA_SENSITIVE, value: true },
        { type: pkcs11js.CKA_PRIVATE, value: true },
        { type: pkcs11js.CKA_SIGN, value: true },
        { type: pkcs11js.CKA_DERIVE, value: true },
        { type: pkcs11js.CKA_MODIFIABLE, value: false },
        { type: pkcs11js.CKA_EXTRACTABLE, value: false },
    ];

    return pkcs11.DeriveBIP32Master(session, seed, publicKeyTemplate, privateKeyTemplate);
}

function deriveChild(session, masterPrivate, path) {
    let publicKeyTemplate = [
        { type: pkcs11js.CKA_TOKEN, value: false },
        { type: pkcs11js.CKA_PRIVATE, value: true },
        { type: pkcs11js.CKA_VERIFY, value: true },
        { type: pkcs11js.CKA_DERIVE, value: false },
        { type: pkcs11js.CKA_MODIFIABLE, value: false },
    ];
    let privateKeyTemplate = [
        { type: pkcs11js.CKA_TOKEN, value: false },
        { type: pkcs11js.CKA_SENSITIVE, value: true },
        { type: pkcs11js.CKA_PRIVATE, value: true },
        { type: pkcs11js.CKA_SIGN, value: true },
        { type: pkcs11js.CKA_DERIVE, value: false },
        { type: pkcs11js.CKA_MODIFIABLE, value: false },
        { type: pkcs11js.CKA_EXTRACTABLE, value: false },
    ];

    return pkcs11.DeriveBIP32Child(session, masterPrivate, publicKeyTemplate, privateKeyTemplate, path);
}

function sign(session, privateKey, data) {
    let mech = {
        mechanism: pkcs11js.CKM_ECDSA,
    };
    pkcs11.C_SignInit(session, mech, privateKey)
    return pkcs11.C_Sign(session, data, Buffer.alloc(64));
}

function verify(session, publicKey, data, signature) {
    let mech = {
        mechanism: pkcs11js.CKM_ECDSA,
    };
    pkcs11.C_VerifyInit(session, mech, publicKey)
    return pkcs11.C_Verify(session, data, signature)
}

function signatureLowS(sig) {
    let r = new BN(sig.slice(0, sig.length / 2).toString('hex'), 16);
    let s = new BN(sig.slice(sig.length / 2).toString('hex'), 16);
    let halfOrder = secp256k1_N.shrn(1);
    if (s.cmp(halfOrder) == 1) {
        s = secp256k1_N.sub(s);
    }
    return Buffer.concat([r.toBuffer("be", 32), s.toBuffer("be", 32)]);
}


/**
 * get public key from point EC
 * @param buffer
 * @return {string}
 */
const getPublicKeyFromPointEC = (buffer) => {
    if (!Buffer.isBuffer(buffer) || (buffer.length !== 67) || (buffer[0] !== 4)) {
        throw new Error("getPublicKeyFromPointEC(): only uncompressed point format supported");
    }
    // According to ASN encoded value, the first 3 bytes are
    // 04 - OCTET STRING
    // 41 - Length 65 bytes
    // For secp256k1 curve it's always 044104 at the beginning
    return `${buffer.slice(2, 67).toString('hex')}`;
}

pkcs11.load(lib);
pkcs11.C_Initialize();

try {

    let slots = pkcs11.C_GetSlotList(true);
    let slot = slots[0];

    let session = pkcs11.C_OpenSession(slot, pkcs11js.CKF_RW_SESSION | pkcs11js.CKF_SERIAL_SESSION);

    pkcs11.C_Login(session, 1, pin);

    let seed = Buffer.alloc(8)
    seed.writeInt32LE(seedHandle);
    let master = deriveMaster(session, seed);
    let child = deriveChild(session, master.privateKey, [0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0, 0]);

    let attr = pkcs11.C_GetAttributeValue(session, child.publicKey, [{ type: pkcs11js.CKA_EC_POINT }])
        .filter(a => a.type === pkcs11js.CKA_EC_POINT)
        .map(a => a.value)
        .at(0)
    console.log(getPublicKeyFromPointEC(attr))

    let hash = sha256("BIP32 Message")
    let data = Buffer.from(hash, "hex");

    let signature = sign(session, child.privateKey, data);
    signature = signatureLowS(signature);
    verify(session, child.publicKey, data, signature);

    pkcs11.C_Logout(session);
    pkcs11.C_CloseSession(session);
}
catch (e) {
    console.error(e);
}
finally {
    pkcs11.C_Finalize();
}
