/*******************************************************************************
 *  Code contributed to the webinos project*
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
 * Copyright 2012 - 2013 Samsung Electronics (UK) Ltd
 * Author: Habib Virji (habib.virji@samsung.com)
 *         Ziran Sun (ziran.sun@samsung.com)
 *******************************************************************************/
var Certificate = function(webinosMetaData, userData) {
    "use strict";
    try{
        var KeyStore = require("webinos-keyStorage");
        var logger   = require("webinos-utilities").webinosLogging(__filename);
    } catch(err) {
        this.emit("MODULE_MISSING", new Error("Required Webinos Modules are Missing "+ err.message));
        return;
    }
    var CertContext = this, certificateType = Object.freeze({ "SERVER": 0, "CLIENT": 1}), certificateManager;
    CertContext.internal={master:{}, conn:{}, web:{}};
    CertContext.external={};
    CertContext.crl = {};
    CertContext.keyStore = new KeyStore(webinosMetaData.webinosType, webinosMetaData.webinosRoot);
    /**
     * Helper function to return certificateManager object
     */
    function getCertificateManager() {
        try {
            if(!certificateManager)
                certificateManager = require ("certificate_manager");
            return certificateManager;
        } catch (err) {
            CertContext.emit("MODULE_MISSING", new Error("Certificate Manager is Missing "+err.message));
            return null;
        }
    }

    /**
     * Helper function to set based on webinosType client or server certificate
     * @param {String} type - Webinos type
     * @return {String} 0 or 1 depending on webinos type
     */
    function getCertType(type) {
        var cert_type;
        if (type === "PzhPCA" || type === "PzhCA" || type === "PzpCA") {
            cert_type = certificateType.SERVER;
        } else if (type === "PzhP" || type === "Pzh" || type === "Pzp" || type === "PzhWS" || type === "PzhSSL" ) {
            cert_type = certificateType.CLIENT;
        }
        return cert_type;
    }

    /**
     * Helper function that assigns a key id depending on the webinos type
     * KeyId is used as a secretKey in keyStore module or as a fileName if keyStore is not available
     * @param {String} type - Webinos type
     * @return {String} key_id based on the webinos type
     */
    function getKeyId(type) {
        var key_id;
        if (type === "PzhPCA" || type === "PzhCA" || type === "PzpCA") {
            key_id = CertContext.internal.master.key_id = webinosMetaData.webinosName + "_master";
        } else if (type === "PzhP" || type === "Pzh" || type === "Pzp") {
            key_id = CertContext.internal.conn.key_id = webinosMetaData.webinosName + "_conn";
        } else if (type === "PzhWS") {
            if(!CertContext.internal.webclient) {CertContext.internal.webclient = {}}
            key_id = CertContext.internal.webclient.key_id = webinosMetaData.webinosName + "_webclient";
        } else if (type === "PzhSSL") {
            if(!CertContext.internal.webssl) {CertContext.internal.webssl = {}}
            key_id = CertContext.internal.webssl.key_id = webinosMetaData.webinosName + "_webssl";
        }
        return key_id;
    }

    function generatePrivateKey(type) {
        var key_id = getKeyId(type), certificateManager, key;
        if ((certificateManager = getCertificateManager())) {
            try {
                if (type === "PzhPCA" ||  type === "PzhCA" || type === "PzpCA"){
                    key = certificateManager.genRsaKey(2048);
                } else {
                    key = certificateManager.genRsaKey(1024);
                }
                CertContext.keyStore.storeKey(key_id, key);
                return key;
            }catch(err) {
                CertContext.emit("FUNC_ERROR", new Error("Failed Generating Private Key "+ err.message));
            }
        }
        return undefined;
    }

    function generateCSR(cn, privateKey) {
        try {
            var certificateManager = getCertificateManager();
            if(certificateManager){
                cn = (encodeURIComponent(cn)).substring (0, 40);
                var csr = certificateManager.createCertificateRequest (privateKey,
                    encodeURIComponent (userData.country),
                    encodeURIComponent (userData.state), // state
                    encodeURIComponent (userData.city), //city
                    encodeURIComponent (userData.orgname), //orgname
                    encodeURIComponent (userData.orgunit), //orgunit
                    cn,
                    encodeURIComponent (userData.email));
                if (!csr) throw "userData is empty or incorrect";
                return csr;
            }
        } catch (err) {
            CertContext.emit("FUNC_ERROR", new Error("Failed Generating CSR. - "+err));
        }
        return undefined;
    }

    function generateSelfSignedCert(type, privateKey, csr) {
        try {
            var certificateManager = getCertificateManager(), cert_type = getCertType(type);
            if(certificateManager){
                var server, cert;
                server = (require ("net").isIP(webinosMetaData.serverName))? "IP:" : "DNS";
                server += webinosMetaData.serverName;
                cert = certificateManager.selfSignRequest (csr, 3600, privateKey, cert_type, server);
                return cert;
            }
        } catch (err) {
            CertContext.emit("FUNC_ERROR", new Error("Failed Self-Signing Certificate - "+err));
        }
        return undefined;
    }

    function generateCRL(privateKey, cert) {
        try {
            var certificateManager = getCertificateManager();
            if(certificateManager){
                return certificateManager.createEmptyCRL (privateKey, cert, 3600, 0);
            }
        } catch (err) {
            CertContext.emit("FUNC_ERROR", new Error("Failed Creating CRL - "+ err));
        }
        return undefined;
    }

    /**
     * Generates a self signed certificate. All webinos devices PZH or PZP generates private key and self signed
     * certificates through this function
     * Server components just run this function, client components after running this component need to run
     * generateSignedCertificate to belong in the same personal zone
     * - Private key - Generates private key using keyStore manager
     * - Certificate sign request - based on user details as read from webinos_config generates a csr
     * - Self Signed certificate - Above generated csr is self signed using own private key
     * - Empty CRL - Empty CRL useful only in PZH case
     * @public
     * @param {String} type -  Webinos type
     * @param {String} cn - It is of format type:webinosName
     * @param {Function} callback - returns just true in case of server if above four functionality are completed.
     *  In case of client, it returns true and csr as they need to get signed by the server certificate. In case of error
     *  it returns false
     */
    this.generateSelfSignedCertificate = function (type, cn, callback) {
        try {
            var privateKey, csr, cert, crl;
            if (type === "PzhCA") {
                CertContext.internal.signedCert = {};
                CertContext.internal.revokedCert = {};
            } else if (type === "PzpCA") {
                CertContext.internal.pzh = {}
            }

            if((privateKey = generatePrivateKey(type))) {
                logger.log (type + " Created Private Key (certificate generation I step)");
                if (csr = generateCSR(cn, privateKey)) {
                    logger.log (type + " Generated CSR (Certificate Generation II step)");
                    if ((cert=generateSelfSignedCert(type, privateKey,csr))) {
                        logger.log (type + " Generated Self-Signed Certificate (certificate generation III step)");
                        if (type === "PzhPCA" || type === "PzhCA" || type === "PzpCA") {
                            CertContext.internal.master.cert = cert;
                            if ((crl = generateCRL(privateKey, cert))) {
                                logger.log (type + " Generated CRL (certificate generation IV step)");
                                CertContext.crl.value = obj.crl;
                                // We need to get it signed by PZH during PZP enrollment
                                if (type === "PzpCA")  CertContext.internal.master.csr = csr;
                                return true;
                            }
                        } else if (type === "PzhP" || type === "Pzh" || type === "Pzp") {
                            CertContext.internal.conn.cert = cert;
                            if (type === "Pzp") CertContext.internal.conn.csr = csr;
                            return obj.csr;
                        }  else if (type === "PzhWS" || type === "PzhSSL") {
                            return obj.csr;
                        }
                    }
                }
            }
        } catch (err) {
            CertContext.emit("EXCEPTION", new Error("Failed Creating Certificates"));
        }
    };

    /**
     * Used by server to sign a client certificate
     * - PZH uses this to sign certificate for the PZP.
     * - PZH Provider uses this to sign web server certificates
     * @public
     * @param {String} csr - Certificate that needs to be signed by the server
     */
    this.generateSignedCertificate = function (csr) {
        try {
            var certificateManager, privateKey;
            if((certificateManager = getCertificateManager())) {
                if((privateKey = CertContext.keyStore.fetchKey(CertContext.internal.master.key_id))){
                    var server,  clientCert;
                    server = (require ("net").isIP(webinosMetaData.serverName))? "IP:" : "DNS";
                    server += webinosMetaData.serverName;
                    try {
                        clientCert = certificateManager.signRequest (csr, 3600, privateKey,
                            CertContext.internal.master.cert, certificateType.CLIENT, server);
                        logger.log ("Signed Certificate by the PZP/PZH");
                        return clientCert;
                    } catch (err) {
                        CertContext.emit("FUNC_ERROR", new Error("Failed Signing Client Certificate "+err.messsage));
                        return undefined;
                    }
                }
            }
        } catch (err) {
            CertContext.emit("EXCEPTION", new Error("Signing Certificate Generated Error "+err.message));
            return undefined;
        }
    };

    /**
     * Fetch hash value from the certificate
     * @public
     * @param {String} certPath - Path where the certificate is located to read hash value
     * @param {Function} callback - true if successful in retrieving hash value else false
     */
    this.getKeyHash = function(certPath, callback){
        try {
            var certificateManager;
            if((certificateManager = getCertificateManager())){
                var hash = certificateManager.getHash(certPath);
                logger.log("Key Hash is" + hash);
                return hash;
            }
        } catch (err) {
            CertContext.emit("EXCEPTION", new Error("GetKey Hash Failed "+err.messsage));
            return undefined;
        }
    };

    /**
     * Revokes a PZP certificate. Revoke functionality is intended to be run only by a Server
     * @param {String} pzpCert - PEM formatted string that needs to be revoked
     */
    this.revokeClientCert = function (pzpCert) {
        try {
            var certificateManager, privateKey;
            if((certificateManager = getCertificateManager())){
                if ((privateKey = CertContext.keyStore.fetchKey(CertContext.internal.master.key_id))) {
                    try {
                        var crl = certificateManager.addToCRL ("" +privateKey, "" + CertContext.crl.value, "" + pzpCert); // master.key.value, master.cert.value
                        logger.log("revoked certificate");
                        return crl;
                    } catch(err){
                        CertContext.emit("FUNC_ERROR", new Error("Certificate Revoke Failed "+ err.message));
                        return undefined;
                    }
                }
            }
        } catch (err) {
            CertContext.emit("EXCEPTION", new Error("Certificate Revoke Failed " + err.message));
            return undefined;
        }
    };
    CertContext.keyStore.on("READ_ERROR", function(errMsg){
        CertContext.emit("READ_ERROR", errMsg);
    });
    CertContext.keyStore.on("WRITE_ERROR", function(errMsg){
        CertContext.emit("WRITE_ERROR", errMsg);
    });
    CertContext.keyStore.on("CLEANUP_ERROR", function(errMsg){
        CertContext.emit("CLEANUP_ERROR", errMsg);
    });
    CertContext.keyStore.on("FUNC_ERROR", function(errMsg){
        CertContext.emit("FUNC_ERROR", errMsg);
    });
};

Certificate.prototype.__proto__ = require("events").EventEmitter.prototype;

if (typeof module !== 'undefined'){
    exports.Certificate = Certificate;
}
module.exports = Certificate;
