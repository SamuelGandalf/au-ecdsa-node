const secp = require("ethereum-cryptography/secp256k1.js");  // imports the secp256k1 library for generating private keys
const {toHex, utf8ToBytes} = require("ethereum-cryptography/utils.js");  // utilities library: hexToBytes, toHex, utf8ToBytes
const {keccak256} = require("ethereum-cryptography/keccak.js");

const privateKey = secp.secp256k1.utils.randomPrivateKey();
console.log("Private Key: ", toHex(privateKey)); 

const publicKey = secp.secp256k1.getPublicKey(privateKey);
console.log("Public Key: ", toHex(keccak256(publicKey)).slice(-20));    // displays only the first 20 bytes of the adddress

//const data = ""
//const hashData = keccak256(utf8ToBytes(data))
function hashData(data){
    return keccak256(utf8ToBytes(data));
}

function generateSignature (privateKey, data){
    let messageHash = keccak256(utf8ToBytes(data));
    return [toHex(secp.secp256k1.sign(messageHash, privateKey)), secp.secp256k1.sign(messageHash, privateKey).recovery];
}

function vldtSignature(sigHex, sigRec, messageHash, sender){
    let sig = secp.secp256k1.Signature.fromCompact(sigHex);
    sig.recovery = sigRec;

    let publicKey = sig.recoverPublicKey(messageHash).toRawBytes();
    if (sender !== getWalletAdr(publicKey)){
        return false;
    }
    secp.secp256k1.verify(sig, messageHash, publicKey);

}

module.exports = {hashData, generateSignature, vldtSignature};

