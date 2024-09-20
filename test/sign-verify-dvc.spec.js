const { signAndPack, unpackAndVerify, makeCWTDVC, parseCWTDVC, debug, addCachedCerts, addCachedKeys} = require('../lib/index');
const expect = require('chai').expect; 

const {CERT_TEST_LIST, PUBKEY_TEST_LIST} = require('./resolver.test.js');

addCachedCerts(CERT_TEST_LIST);
addCachedKeys(PUBKEY_TEST_LIST);

const PUBLIC_KEY_PEM = '-----BEGIN CERTIFICATE-----\nMIIBYDCCAQYCEQCAG8uscdLb0ppaneNN5sB7MAoGCCqGSM49BAMCMDIxIzAhBgNV\nBAMMGk5hdGlvbmFsIENTQ0Egb2YgRnJpZXNsYW5kMQswCQYDVQQGEwJGUjAeFw0y\nMTA0MjcyMDQ3MDVaFw0yNjAzMTIyMDQ3MDVaMDYxJzAlBgNVBAMMHkRTQyBudW1i\nZXIgd29ya2VyIG9mIEZyaWVzbGFuZDELMAkGA1UEBhMCRlIwWTATBgcqhkjOPQIB\nBggqhkjOPQMBBwNCAARkJeqyO85dyR+UrQ5Ey8EdgLyf9NtsCrwORAj6T68/elL1\n9aoISQDbzaNYJjdD77XdHtd+nFGTQVpB88wPTwgbMAoGCCqGSM49BAMCA0gAMEUC\nIQDvDacGFQO3tuATpoqf40CBv09nfglL3wh5wBwA1uA7lAIgZ4sOK2iaaTsFNqEN\nAF7zi+d862ePRQ9Lwymr7XfwVm0=\n-----END CERTIFICATE-----';
const PRIVATE_KEY_P8 = '-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZgp3uylFeCIIXozb\nZkCkSNr4DcLDxplZ1ax/u7ndXqahRANCAARkJeqyO85dyR+UrQ5Ey8EdgLyf9Nts\nCrwORAj6T68/elL19aoISQDbzaNYJjdD77XdHtd+nFGTQVpB88wPTwgb\n-----END PRIVATE KEY-----';

const TEST_PAYLOAD = {
  "n" : "Aulo Agerio",
  "dob" : "1905-08-23",
  "s" : "M",
  "ntl" : "CL",
  "nid" : "16337361-9",
  "gn" : "Parent/Juan Medina",
  "v" : {
    "dn" : "Primary",
    "tg" : "1D47",
    "vp" : "XM0N24",
    "ma" : "HIPRA",
    "dt" : "1904-08-23",
    "bo" : "123123123",
    "mp" : "1",
    "mid" : "25",
    "vls" : "2015-02-07",
    "vle" : "2015-02-07",
    "cn" : "Vacunador",
    "is" : "reference to organzation"
  }
};

describe('DVC', function() {

  it('should Make CWT DVC', async () => {
    const cwtPayload = await makeCWTDVC(TEST_PAYLOAD, null, "XCL");
    expect(await parseCWTDVC(cwtPayload)).to.eql(TEST_PAYLOAD);
  });

  it('should Sign Pack and Unpack Verify a json using Base45 of CWT DVC', async () => {
    const cwtPayload = await makeCWTDVC(TEST_PAYLOAD, null, "XCL");
    const signed = await signAndPack(cwtPayload, PUBLIC_KEY_PEM, PRIVATE_KEY_P8);
    const result = await unpackAndVerify(signed);
    expect(result.status).to.be.equals("verified");
    expect(await parseCWTDVC(result.contents)).to.eql(TEST_PAYLOAD);

  });

});
