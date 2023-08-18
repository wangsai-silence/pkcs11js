let pkcs11js = require("pkcs11js");


let pkcs11 = new pkcs11js.PKCS11();


let lib = "/usr/safenet/lunaclient/lib/libCryptoki2_64.so"
let pin = "pin123!"

function generateSeed(session) {
    let seedTemplate = [
        { type: pkcs11js.CKA_KEY_TYPE, value: pkcs11js.CKK_GENERIC_SECRET },
        { type: pkcs11js.CKA_TOKEN, value: true },  //标记为true则会保存数据
        { type: pkcs11js.CKA_DERIVE, value: true },
        { type: pkcs11js.CKA_PRIVATE, value: true },
        { type: pkcs11js.CKA_EXTRACTABLE, value: false },
        { type: pkcs11js.CKA_MODIFIABLE, value: false },
        { type: pkcs11js.CKA_VALUE_LEN, value: 32 }
    ];

    return pkcs11.C_GenerateKey(session, { mechanism: pkcs11js.CKM_GENERIC_SECRET_KEY_GEN }, seedTemplate);
}

pkcs11.load(lib);
pkcs11.C_Initialize();

try {

    let slots = pkcs11.C_GetSlotList(true);
    let slot = slots[0];

    let session = pkcs11.C_OpenSession(slot, pkcs11js.CKF_RW_SESSION | pkcs11js.CKF_SERIAL_SESSION);

    pkcs11.C_Login(session, 1, pin);

    let seed = generateSeed(session);

    console.log(`seed key handle:${seed.readInt32LE(0)}`)

    pkcs11.C_Logout(session);
    pkcs11.C_CloseSession(session);
}
catch (e) {
    console.error(e);
}
finally {
    pkcs11.C_Finalize();
}
