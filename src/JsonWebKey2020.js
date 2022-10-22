const JWK = require('./JWK');
const JWS = require('./JWS');

class JsonWebKey2020 {
  static async generate(alg) {
    const k = await JWK.generateKeyPair(alg);
    return new JsonWebKey2020(k);
  }

  static async from(keypair) {
    return new JsonWebKey2020(keypair);
  }

  constructor({id, type, controller, publicKeyJwk, privateKeyJwk}) {
    this.id = id || '#0';
    this.type = type || 'JsonWebKey2020';
    this.controller = controller || publicKeyJwk.kid;
    this.publicKeyJwk = publicKeyJwk;
    this.privateKeyJwk = privateKeyJwk;
  }

  async sign(data) {
    return JWS.signDetached(data, this.privateKeyJwk);
  }

  async verify(data, signature) {
    return JWS.verifyDetached(data, signature, this.publicKeyJwk);
  }
}

module.exports = JsonWebKey2020;
