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
