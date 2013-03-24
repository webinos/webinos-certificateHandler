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
var Certificate = function(webinosType, webinosRoot,  webinosName, serverName_) {
    "use strict";    
    var dependency = require ("find-dependencies") (__dirname);
    var KeyStore = dependency.global.require (dependency.global.manager.keystore.location);
    var logger = dependency.global.require(dependency.global.util.location, "lib/logging.js") (__filename);
    var CertContext = this, certificateType = Object.freeze({ "SERVER": 0, "CLIENT": 1}), certificateManager;
    CertContext.cert = {internal:{master:{}, conn:{}, web:{}}, external:{}};
    CertContext.keyStore = new KeyStore(webinosType, webinosRoot);
    /**
     * Helper function to return certificateManager object
     * @param {Function} callback - true if certificate loaded else false
     */
    function getCertificateManager(callback) {
        try {
            if(!certificateManager)
                certificateManager = require ("certificate_manager");
            callback(true, certificateManager);
        } catch (err) {
            CertContext.on("MODULE_MISSING", "Certificate Manager is missing", err);
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
            key_id = CertContext.cert.internal.master.key_id = webinosName + "_master";
        } else if (type === "PzhP" || type === "Pzh" || type === "Pzp") {
            key_id = CertContext.cert.internal.conn.key_id = webinosName + "_conn";
        } else if (type === "PzhWS") {
            if(!CertContext.cert.internal.webclient) {CertContext.cert.internal.webclient = {}}
            key_id = CertContext.cert.internal.webclient.key_id = webinosName + "_webclient";
        } else if (type === "PzhSSL") {
            if(!CertContext.cert.internal.webssl) {CertContext.cert.internal.webssl = {}}
            key_id = CertContext.cert.internal.webssl.key_id = webinosName + "_webssl";
        }
        return key_id;
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
            var obj = {}, key_id = getKeyId(type), cert_type = getCertType(type);
            if (type === "PzhCA") {
                CertContext.cert.internal.signedCert = {};
                CertContext.cert.internal.revokedCert = {};
            } else if (type === "PzpCA") {
                CertContext.cert.internal.pzh = {}
            }
            cn = encodeURIComponent(cn);

            if (cn.length > 40) {
                cn = cn.substring (0, 40);
            }
            getCertificateManager(function(status, certificateManager) {
                if (status) {
                    CertContext.keyStore.generateStoreKey(type, key_id, function (status, privateKey) {
                        if (status) {
                            logger.log (type + " created private key (certificate generation I step)");
                            try {
                                obj.csr = certificateManager.createCertificateRequest (privateKey,
                                    encodeURIComponent (CertContext.userData.country),
                                    encodeURIComponent (CertContext.userData.state), // state
                                    encodeURIComponent (CertContext.userData.city), //city
                                    encodeURIComponent (CertContext.userData.orgname), //orgname
                                    encodeURIComponent (CertContext.userData.orgunit), //orgunit
                                    cn,
                                    encodeURIComponent (CertContext.userData.email));
                                if (!obj.csr) throw "userData is empty";
                            } catch (err) {
                                CertContext.emit("FUNC_ERROR", "failed generating CSR. user details are missing", err);
                                return;
                            }

                            try {
                                logger.log (type + " generated CSR (certificate generation II step)");
                                var serverName;
                                if (require("net").isIP(serverName_)) {
                                    serverName = "IP:" + serverName_;
                                } else {
                                    serverName = "DNS:" + serverName_;
                                }
                                obj.cert = certificateManager.selfSignRequest (obj.csr, 3600, privateKey, cert_type, serverName);
                            } catch (err1) {
                                CertContext.emit("FUNC_ERROR", "failed self signing certificate", err1);
                            }
                            logger.log (type + " generated self signed certificate (certificate generation III step)");
                            if (type === "PzhPCA" || type === "PzhCA" || type === "PzpCA") {
                                CertContext.cert.internal.master.cert = obj.cert;
                                try {
                                    obj.crl = certificateManager.createEmptyCRL (privateKey, obj.cert, 3600, 0);
                                } catch (err2) {
                                    CertContext.emit("FUNC_ERROR", "failed creating crl", err2);
                                    return;
                                }
                                logger.log (type + " generated crl (certificate generation IV step)");
                                CertContext.crl.value = obj.crl;
                                if (type === "PzpCA") { CertContext.cert.internal.master.csr = obj.csr;} // We need to get it signed by PZH during PZP enrollment
                                return callback(true);
                            } else if (type === "PzhP" || type === "Pzh" || type === "Pzp") {
                                CertContext.cert.internal.conn.cert = obj.cert;
                                if (type === "Pzp") { CertContext.cert.internal.conn.csr = obj.csr; }
                                return callback (true, obj.csr);
                            }  else if (type === "PzhWS" || type === "PzhSSL") {
                                return callback (true, obj.csr);
                            }
                        }
                    });
                } 
            });
        } catch (err) {
            CertContext.emit("EXCEPTION", "FAILED Creating Certificates", err);
        }
    };

    /**
     * Used by server to sign a client certificate
     * - PZH uses this to sign certificate for the PZP.
     * - PZH Provider uses this to sign web server certificates
     * @public
     * @param {String} csr - Certificate that needs to be signed by the server
     * @param {Function} callback - if certificate has been signed successfully then return true and signed certificate
     * else return false
     */
    this.generateSignedCertificate = function (csr, callback) {
        try {
            getCertificateManager(function(status, certificateManager){
                if (status) {
                    CertContext.keyStore.fetchKey(CertContext.cert.internal.master.key_id, function (status, privateKey) {
                        if (status) {
                            var server,  clientCert;
                            if (require ("net").isIP (serverName_)) {
                                server = "IP:" + serverName_;
                            } else {
                                server = "DNS:" + serverName_;
                            }
                            clientCert = certificateManager.signRequest (csr, 3600, privateKey,
                                            CertContext.cert.internal.master.cert, certificateType.CLIENT, server);
                            logger.log ("signed certificate by the PZP/PZH");
                            callback (true, clientCert);
                        } 
                    });
                }
            });
        } catch (err) {
            CertContext.emit("EXCEPTION", "signing error", err);                
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
            getCertificateManager(function(status, certificateManager){
                if (status) {
                    var hash = certificateManager.getHash(certPath);
                    logger.log("Key Hash is" + hash);
                    callback(true, hash);
                } 
            });
        } catch (err) {
            CertContext.emit("EXCEPTION", "getKey hash failed", err);         
        }
    };

    /**
     * Revokes a PZP certificate. Revoke functionality is intended to be run only by a Server
     * @param {String} pzpCert - PEM formatted string that needs to be revoked
     * @param {Function} callback - true if revoke was successful else false
     */
    this.revokeClientCert = function (pzpCert, callback) {
        try {
            getCertificateManager(function(status, certificateManager){
                if(status) {
                    CertContext.keyStore.fetchKey(CertContext.cert.internal.master.key_id, function (status, value) {
                        if (status) {
                            var crl = certificateManager.addToCRL ("" + value, "" + CertContext.crl.value, "" + pzpCert);
                            // master.key.value, master.cert.value
                            logger.log("revoked certificate");
                            callback (true, crl);
                        } 
                    });
                } 
            });
        } catch (err) {
            CertContext.emit("EXCEPTION", "certificate revoke failed", err);
        }
    };
};

KeyStore.prototype.__proto__ = require("events").EventEmitter.prototype;

if (typeof module !== 'undefined'){
    exports.Certificate = Certificate;    
}
module.exports = Certificate;
