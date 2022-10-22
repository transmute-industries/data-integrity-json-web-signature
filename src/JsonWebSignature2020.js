const jsonld = require('jsonld');
const crypto = require('crypto');

const JsonWebKey2020 = require('./JsonWebKey2020');

const sha256 = (input) => {
  return crypto.createHash('sha256').update(input).digest();
};

const dereference = (id, didDocument) => {
  return didDocument.verificationMethod.find((vm) => {
    return id.endsWith(vm.id);
  });
};

class JsonWebSignature2020 {
  static async fromDocumentLoader({id, documentLoader}) {
    const vm = await documentLoader(id);
    const key = new JsonWebKey2020(vm);
    return new JsonWebSignature2020({key});
  }

  constructor({key, documentLoader}) {
    this.key = key;
    this.documentLoader = documentLoader;
  }

  keyId() {
    return this.key.id.startsWith('#') ?
      this.key.controller + this.key.id :
      this.key.id;
  }

  async canonize({document, documentLoader}) {
    const clonedDocument = JSON.parse(JSON.stringify(document));
    return jsonld.canonize(clonedDocument, {
      algorithm: 'URDNA2015',
      format: 'application/n-quads',
      documentLoader,
    });
  }

  async createVerifyData({document, proof, documentLoader}) {
    const clonedDocument = JSON.parse(JSON.stringify(document));
    const clonedProof = JSON.parse(JSON.stringify(proof));
    delete clonedProof['jws'];
    const c14nProofOptions = await this.canonize({
      document: clonedProof,
      documentLoader,
    });
    const c14nDocument = await this.canonize({
      document: clonedDocument,
      documentLoader,
    });
    return Buffer.concat([sha256(c14nProofOptions), sha256(c14nDocument)]);
  }

  async getProof({document, documentLoader}) {
    const clonedDocument = JSON.parse(JSON.stringify(document));
    const proof = {
      '@context': clonedDocument['@context'],
      'type': 'JsonWebSignature2020',
      'verificationMethod': this.keyId(),
      'proofPurpose': 'assertionMethod',
      'created': new Date().toISOString(),
    };
    const verifyData = await this.createVerifyData({
      document: clonedDocument,
      proof,
      documentLoader,
    });
    // console.log('sign: ', verifyData.toString('hex'));
    const signature = await this.key.sign(verifyData);
    proof.jws = signature;
    delete proof['@context'];
    return proof;
  }

  async addProof({document, documentLoader}) {
    const clonedDocument = JSON.parse(JSON.stringify(document));
    clonedDocument.proof = await this.getProof({
      document: clonedDocument,
      documentLoader,
    });
    return clonedDocument;
  }

  async verifyProof({document, proof, documentLoader}) {
    const clonedDocument = JSON.parse(JSON.stringify(document));
    const clonedProof = JSON.parse(JSON.stringify(proof));
    clonedProof['@context'] = clonedDocument['@context'];
    const verifyData = await this.createVerifyData({
      document: clonedDocument,
      proof: clonedProof,
      documentLoader,
    });
    // console.log('verify: ', verifyData.toString('hex'));
    const verified = await this.key.verify(verifyData, proof.jws);
    return verified;
  }

  async verify({document}) {
    const {verificationMethod} = document.proof;
    if (!verificationMethod) {
      throw new Error('No verificationMethod found in proof');
    }
    const resolved = await this.documentLoader(verificationMethod);
    const vm = await dereference(verificationMethod, resolved.document);
    this.key = new JsonWebKey2020(vm);
    const {proof, ...rest} = document;
    return this.verifyProof({
      document: rest,
      proof,
      documentLoader: this.documentLoader,
    });
  }
}

module.exports = JsonWebSignature2020;
