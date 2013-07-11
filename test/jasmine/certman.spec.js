/*******************************************************************************
*  Code contributed to the webinos project
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
* 
*     http://www.apache.org/licenses/LICENSE-2.0
* 
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* Copyright 2011 University of Oxford
*******************************************************************************/
// test for the openssl wrapper.
// TODO: more than just checks for not-empty, need to check some fields
// there is an x509 module somewhere I need to use...

var certman = require("certificate_manager");

var util = require("util");
var rsakey;
var certReq;
var ssCert;
var cert;
var childKey;
var childReq;
var childCert;
var emptyCRL;

var RSA_START       = "-----BEGIN RSA PRIVATE KEY-----";
var RSA_END         = "-----END RSA PRIVATE KEY-----";
var CERT_REQ_START  = "-----BEGIN CERTIFICATE REQUEST-----";
var CERT_REQ_END    = "-----END CERTIFICATE REQUEST-----";
var CERT_START      = "-----BEGIN CERTIFICATE-----";
var CERT_END        = "-----END CERTIFICATE-----";
var CRL_START       = "-----BEGIN X509 CRL-----";
var CRL_END         = "-----END X509 CRL-----";


describe("generate keys", function() {
    it("can create a 1024 size key", function() {       
        rsakey = certman.genRsaKey(1024);
        expect(rsakey).not.toBeNull();
        expect(rsakey).not.toEqual("");
        expect(rsakey).toContain(RSA_START);
        expect(rsakey).toContain(RSA_END);
        expect(rsakey.length).toBeGreaterThan(100);
    });
    it("can create a bigger key", function() {
        var rsakey2 = certman.genRsaKey(2048);
        expect(rsakey).not.toEqual(rsakey2);
    });
});

describe("generate certificate requests", function() {
    it("can create a certificate request", function() {       
        certReq = certman.createCertificateRequest(rsakey, 
            "UK","OX","Oxford","Univ. Oxford","Computer Science","Pzh:CA Key", "john.lyle@cs.ox.ac.uk");
        expect(certReq).not.toBeNull();
        expect(certReq).toContain(CERT_REQ_START);
        expect(certReq).toContain(CERT_REQ_END);
        expect(certReq.length).toBeGreaterThan(100);
    });
});

describe("sign certificate requests", function() {
    it("can self-sign a certificate request", function() {
        ssCert = certman.selfSignRequest(certReq, 30, rsakey, 1, "URI:pzh.webinos.org");
        expect(ssCert).not.toBeNull();
        expect(ssCert).toContain(CERT_START);
        expect(ssCert).toContain(CERT_END);
        expect(ssCert.length).toBeGreaterThan(100);
    });
    
    it("can sign another certificate request", function() {
        childKey = certman.genRsaKey(1024);
        childReq = certReq = certman.createCertificateRequest(rsakey, 
            "UK","OX","Oxford","Univ. Oxford","Computer Science", "Pzp:Client Key", "john.lyle@cs.ox.ac.uk");
        childCert = certman.signRequest(childReq, 30, rsakey, ssCert, 1, "URI:pzh.webinos.org");
        expect(childCert).not.toBeNull();
        expect(childCert).toContain(CERT_START);
        expect(childCert).toContain(CERT_END);
        expect(childCert.length).toBeGreaterThan(100);
    });
});

describe("create certificate revocation lists", function() {
    it("can create an empty CRL", function() {
        emptyCRL = certman.createEmptyCRL(rsakey, ssCert, 30, 0);
        expect(emptyCRL).not.toBeNull();
        expect(emptyCRL).toContain(CRL_START);
        expect(emptyCRL).toContain(CRL_END);
        expect(emptyCRL.length).toBeGreaterThan(50);
    });
    it("can add to a CRL", function() {
        newCRL = certman.addToCRL(rsakey, emptyCRL, childCert);
        expect(newCRL).not.toBeNull();
        expect(newCRL).toContain(CRL_START);
        expect(newCRL).toContain(CRL_END);
        expect(newCRL.length).toBeGreaterThan(50);
        expect(newCRL).not.toEqual(emptyCRL);
    });
});
    
describe("Proper error handling", function() {
    it("will error given a bad altname", function() {
        childKey = certman.genRsaKey(1024);
        childReq = certReq = certman.createCertificateRequest(rsakey, 
            "UK","OX","Oxford","Univ. Oxford","Computer Science", "Client Key", "john.lyle@cs.ox.ac.uk");
        try {
            childCert = certman.signRequest(childReq, 30, rsakey, ssCert, 1, "foo://bar");
            expect(childCert).toBeNull(); //shouldn't get here.
        } catch (err) {
            expect(err).not.toBeGreaterThan(0);
            expect(err.toString()).toEqual("Error: Failed to sign a certificate");
        }
    });
});    

/*
 * TODO: Enable these tests.  At present, these rely on the rest of the 
 * webinos modules working.
 */
var CertificateManager = require("../../lib/certificate");
var WebinosPath = require("webinos-utilities").webinosPath;
var webinosName = "WebinosPZP";
var certConfig = require("../../config.json").params;
var metaData  = {
    webinosType: "Pzp",
    webinosRoot: WebinosPath.webinosPath(),
    webinosName: webinosName,
    serverName: "0.0.0.0"
};
if(!require("fs").existsSync(WebinosPath.webinosPath())) {
    require("fs").mkdirSync(WebinosPath.webinosPath());
    require("fs").mkdirSync(WebinosPath.webinosPath()+"/keys/");
    require("fs").mkdirSync(WebinosPath.webinosPath()+"/certificates/");
    require("fs").mkdirSync(WebinosPath.webinosPath()+"/certificates/internal/");
    require("fs").mkdirSync(WebinosPath.webinosPath()+"/certificates/external/");
}
var CertificateManagerInstance = new CertificateManager(metaData, certConfig);

describe("CertificateManager Server JS tests", function() {
    it("generates server private key, csr, self signed certificate and crl", function() {
        var cn ="PzpCA:" +  webinosName;
        var csr = CertificateManagerInstance.generateSelfSignedCertificate("PzpCA", cn);
	    expect(csr).toBeTruthy();
        expect(CertificateManagerInstance.internal.master.cert).toContain(CERT_START);
        expect(CertificateManagerInstance.internal.master.cert).toContain(CERT_END);
        expect(CertificateManagerInstance.crl.value).toContain(CRL_START);
        expect(CertificateManagerInstance.crl.value).toContain(CRL_END);
        expect(CertificateManagerInstance.internal.master.key_id).toEqual(webinosName + "_master");
    });
    var cn ="Pzp:" + webinosName, csr, signedCert, crl;
    it("generate connection certificate", function() {
        csr = CertificateManagerInstance.generateSelfSignedCertificate("Pzp", cn);
        expect(csr).not.toBeNull();
        expect(csr).not.toEqual("");
        expect(csr).toContain(CERT_REQ_START);
        expect(csr).toContain(CERT_REQ_END);
        expect(CertificateManagerInstance.internal.conn.cert ).toContain(CERT_START);
        expect(CertificateManagerInstance.internal.conn.cert).toContain(CERT_END);
        expect(CertificateManagerInstance.internal.conn.key_id).toEqual(webinosName + "_conn");        
    });
    it("signed connection certificate by the master certificate", function() { // Signed certificate back by PZP
        signedCert = CertificateManagerInstance.generateSignedCertificate(csr);
        expect(signedCert).not.toBeNull();
        expect(signedCert).not.toEqual("");
        expect(signedCert).toContain(CERT_START);
        expect(signedCert).toContain(CERT_END);
    });
    it("revoke PZP certificate", function() {// Revoke PZP certificate
        crl = CertificateManagerInstance.revokeClientCert(signedCert);
        expect(crl).not.toBeNull();
        expect(crl).not.toEqual("");
        expect(crl).toContain(CRL_START);
        expect(crl).toContain(CRL_END);        
    });
});

describe("CertificateManager Negative JS tests", function() {
    CertificateManagerInstance.on("FUNC_ERROR", function(errText, err) {
        console.log("FUNC_ERROR", errText , err);
        expect(errText).not.toBeNull();
        if(errText === "failed generating CSR. user details are missing" ||
            errText === "failed signing client certificate") ;
        else throw "functionality error " + err;
    });
    CertificateManagerInstance.on("EXCEPTION", function(error, errMsg) {
      console.log("EXCEPTION", error ,  errMsg);
   });

    it("csr and signed cert error", function() {
        CertificateManagerInstance.generateSelfSignedCertificate("Pzp", "");
        CertificateManagerInstance.generateSignedCertificate(undefined);
    });
});
describe("get hash", function() {
    it("can get hash of public certificate", function() {
        var path = require("path").join(__dirname,"../conn.pem");
        var hash = certman.getHash(path);
        expect(hash).not.toBeNull();
        expect(hash).not.toEqual([]);
    });
});

describe("parse certificate", function() {
    it("parse certificate", function() {
        var path = require("path").join(__dirname,"../conn.pem");
        var parseCert = CertificateManagerInstance.parseCert((require("fs").readFileSync(path)).toString());
        expect(parseCert).not.toBeNull();
        expect(parseCert.version).toEqual(3);
        expect(parseCert.subject).not.toBeNull();
        expect(parseCert.subject.CN).toContain("PzhWS");
        expect(parseCert.issuer).not.toBeNull();
        expect(parseCert.issuer.CN).toContain("PzhPCA");
        expect(parseCert.serial).not.toBeNull();
        expect(parseCert.validFrom).not.toBeNull();
        expect(parseCert.validTo).not.toBeNull();
        expect(parseCert.publicKeyAlgorithm).not.toBeNull();
        expect(parseCert.publicKey).not.toBeNull();
        expect(parseCert.signatureAlgorithm).not.toBeNull();
        expect(parseCert.signature).not.toBeNull();
        expect(parseCert.fingerPrint).not.toBeNull();
    });
});
describe("parse crl", function() {
    it("crl", function() {
        var path = require("path").join(__dirname,"../crl.pem");
        var parseCrl = CertificateManagerInstance.parseCrl((require("fs").readFileSync(path)).toString());
        expect(parseCrl).not.toBeNull();
        expect(parseCrl.version).toEqual(1);
        expect(parseCrl.lastUpdate).not.toBeNull();
        expect(parseCrl.nextUpdate).not.toBeNull();
        expect(parseCrl.signatureAlg).not.toBeNull();
        expect(parseCrl.signature).not.toBeNull();
        expect(parseCrl.issuer).not.toBeNull();
        expect(parseCrl.issuer.CN).not.toBeNull();
    });
});

describe("validate certificate based on CAList", function() {
    var path, result, status, caList= [(require("fs").readFileSync(require("path").join(__dirname, "pzh_ca.pem"))).toString(),
        (require("fs").readFileSync(require("path").join(__dirname, "pzhp_ca.pem"))).toString(),
        (require("fs").readFileSync(require("path").join(__dirname, "pzp_ca.pem"))).toString()];
    it("validate PZH CA certificate", function() {
        path = require("fs").readFileSync(require("path").join(__dirname,"pzh_ca.pem")).toString();
        result =   CertificateManagerInstance.parseCert(path, "pem");
        status = CertificateManagerInstance.validateConnection(result.issuer.CN, caList);
        expect(status).toBeTruthy();
    });
    it("validate PZH CONN certificate", function() {
        path =  require("fs").readFileSync(require("path").join(__dirname,"pzh_conn")).toString();
        result =   CertificateManagerInstance.parseCert(path, "pem");
        status = CertificateManagerInstance.validateConnection(result.issuer.CN, caList);
        expect(status).toBeTruthy();
    });
    it("validate PZH Provider CA certificate", function() {
        path =  require("fs").readFileSync(require("path").join(__dirname,"pzhp_ca.pem")).toString();
        result =   CertificateManagerInstance.parseCert(path, "pem");
        status = CertificateManagerInstance.validateConnection(result.issuer.CN, caList);
        expect(status).toBeTruthy();
    });
    it("validate PZH WebSSL certificate", function() {
        path =  require("fs").readFileSync(require("path").join(__dirname,"pzh_webssl.pem")).toString();
        result =   CertificateManagerInstance.parseCert(path, "pem");
        status = CertificateManagerInstance.validateConnection(result.issuer.CN, caList);
        expect(status).toBeTruthy();
    });
    it("validate PZP CA certificate", function() {
        path =  require("fs").readFileSync(require("path").join(__dirname,"pzp_ca.pem")).toString();
        result =   CertificateManagerInstance.parseCert(path, "pem");
        status = CertificateManagerInstance.validateConnection(result.issuer.CN, caList);
        expect(status).toBeTruthy();
    });
    it("validate PZP CONN certificate", function() {
        path =  require("fs").readFileSync(require("path").join(__dirname,"pzp_conn.pem")).toString();
        result =   CertificateManagerInstance.parseCert(path, "pem");
        status = CertificateManagerInstance.validateConnection(result.issuer.CN, caList);
        expect(status).toBeTruthy();
    });
    it("validate PZP CONN certificate chain with length one", function() {
        var path =  require("fs").readFileSync(require("path").join(__dirname,"pzp_conn.pem")).toString();
        status = CertificateManagerInstance.validateCertificateChain([path], caList);
        expect(status).toBeTruthy();
    });
    it("negative test - check if verificatio fails if we do not have valid certificate", function(){
        path =  require("fs").readFileSync(require("path").join(__dirname,"pzp_conn.pem")).toString();
        result =   CertificateManagerInstance.parseCert(path, "pem");
        var tmpList= [(require("fs").readFileSync(require("path").join(__dirname, "pzhp_ca.pem"))).toString()];
        status = CertificateManagerInstance.validateConnection(result.issuer.CN, tmpList);
        expect(status).toBeFalsy();
    });
});
