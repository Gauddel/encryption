const ecies = require("eth-ecies");
const eutil = require('ethereumjs-util');
const CryptoJS = require("crypto-js");

// TODO Implement error handling
wallet.updatePluginState({
  cidToEncrytedPassword: [],
})

wallet.onMetaMaskEvent('tx:status-update', (id, status) => {
})

wallet.registerRpcMessageHandler(async (originString, requestObject) => {
  switch (requestObject.method) {
    case 'savePasswordAsSignee' :
      const cid = requestObject.params[0]
      const encryptedPassword = requestObject.params[1]
      return savePasswordAsSignee(cid, encryptedPassword)
    case 'savePasswordAsCreator':
      const cid1 = requestObject.params[0]
      const password = requestObject.params[1]
      return savePasswordAsCreator(cid1, password)
    case 'getEncryptedPassword':
      const cid2 = requestObject.params[0]
      return getEncryptedPassword(cid2)
    case 'encryptFile':
      const file = requestObject.params[0]
      const password1 = requestObject.params[1]
      return encryptFile(file, password1)
    case 'decryptFile':
      const encrytedFile = requestObject.params[0]
      const cid3 = requestObject.params[1]
      return decryptFile(encrytedFile, cid3)
    case 'getAccount':
      return getPubKeyFromExternalCall()
    case 'encryptData':
      const publicKey = requestObject.params[0]
      const data = requestObject.params[1]
      return encrypt(publicKey, data)
    case 'decryptData' : 
      const privateKey = requestObject.params[0]
      const encryptedData = requestObject.params[1]
      return decrypt(privateKey, encryptedData)
    case 'encryptWithCounterpartyPublicKey' :
      const cid4 = requestObject.params[0]
      const counterpartyPublicKey = requestObject.params[1]
      return encryptWithCounterpartyPublicKey(cid4, counterpartyPublicKey)
    default:
      throw new Error('Method not found.')
  }
})

// Encrypt File and Save encrypted Password

async function savePasswordAsSignee(cid, encryptedPassword) {
  var cidToEncrytedPassword = currentPluginState.cidToEncrytedPassword;
  await wallet.updatePluginState({
    ...currentPluginState,
    cidToEncrytedPassword : [...cidToEncrytedPassword, {'cid' : cid, 'encryptedPassword' : encryptedPassword}],
  })
}

async function savePasswordAsCreator(cid, password) {
  var publicKey = await getPubKey();
  var encryptedPassword = await encrypt(publicKey, password);

  var currentPluginState = await wallet.getPluginState();

  var cidToEncrytedPassword = currentPluginState.cidToEncrytedPassword;
  await wallet.updatePluginState({
    ...currentPluginState,
    cidToEncrytedPassword : [...cidToEncrytedPassword, {'cid' : cid, 'encryptedPassword' : encryptedPassword}],
  })
  return {'cid' : cid, 'encryptedPassword' : encryptedPassword};
}

async function getEncryptedPassword(cid) {
  var currentPluginState = await wallet.getPluginState();

  var cidToEncrytedPassword = currentPluginState.cidToEncrytedPassword;
  var encryptedPassword = null;
  for( var i=0; i < cidToEncrytedPassword.length; i++) {
    if(cidToEncrytedPassword[i].cid === cid) {
      encryptedPassword = cidToEncrytedPassword[i].encryptedPassword;
    }
  }

  return encryptedPassword;
}

async function encryptFile(file, password) {
  var wordArray = CryptoJS.lib.WordArray.create((new Uint8Array(Object.values(file))).buffer);
  var encrypted = CryptoJS.AES.encrypt(wordArray, password).toString();

  return encrypted;
}

async function decryptFile(encrytedFile, cid) {
  var encryptedPassword = await getEncryptedPassword(cid);
  console.log(encryptedPassword);
  var password = await decrypt(encryptedPassword);
  console.log('TEST');

  var decryptedFile = CryptoJS.AES.decrypt(encrytedFile, password);

  return decryptedFile.toString(CryptoJS.enc.Base64);
}

// Encrypt File and Save encrypted Password

async function getPubKey() {
  const PRIV_KEY = await wallet.getAppKey();
  return eutil.privateToPublic(eutil.sha256(Buffer(PRIV_KEY)));
}

async function getPubKeyFromExternalCall() {
  const PRIV_KEY = await wallet.getAppKey();
  const pubKey = eutil.bufferToHex(eutil.privateToPublic(eutil.sha256(Buffer(PRIV_KEY))));
  return pubKey;
}

// Encrypt shared password to decrypt the encrypted file in ipfs

async function encrypt(publicKey, data) {
  let adverPublicKey = new Buffer(Object.values(publicKey), 'hex');
  let bufferData = new Buffer(data);

  let encryptedData = ecies.encrypt(adverPublicKey, bufferData);
  return encryptedData.toString('base64');
}

async function decrypt(encryptedData) {
  let privateKey = eutil.sha256(Buffer(await wallet.getAppKey()));
  let userPrivateKey = new Buffer(privateKey, 'hex');
  let bufferEncryptedData = new Buffer(encryptedData, 'base64');

  let decryptedData = ecies.decrypt(userPrivateKey, bufferEncryptedData);
    
  return decryptedData.toString('utf8');
}

async function encryptWithCounterpartyPublicKey(cid, counterpartyPublicKey) {
  console.log(cid);
  console.log(counterpartyPublicKey);
  var encryptedPassword = await getEncryptedPassword(cid);
  console.log(encryptedPassword);
  var decrytedPassword = await decrypt(encryptedPassword);
  console.log(decrytedPassword);

  return await encrypt(counterpartyPublicKey, decrytedPassword);
}

// Encrypt shared password to decrypt the encrypted file in ipfs