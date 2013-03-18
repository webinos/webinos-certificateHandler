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
var dependency = require ("find-dependencies") (__dirname);
var KeyStore = dependency.global.require (dependency.global.manager.keystore.location);

var Certificate = function() {
    "use strict";
    KeyStore.call(this);
    var logger = dependency.global.require(dependency.global.util.location, "lib/logging.js") (__filename);
    var CurrentContext = this, certificateType = Object.freeze({ "SERVER": 0, "CLIENT": 1}), certificateManager;
    CurrentContext.cert = {internal:{master:{}, conn:{}, web:{}}, external:{}};

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
            CurrentContext.on("MODULE_MISSING", "Certificate Manager is missing", err);
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
            key_id = CurrentContext.cert.internal.master.key_id = CurrentContext.metaData.webinosName + "_master";
        } else if (type === "PzhP" || type === "Pzh" || type === "Pzp") {
            key_id = CurrentContext.cert.internal.conn.key_id = CurrentContext.metaData.webinosName + "_conn";
        } else if (type === "PzhWS") {
            if(!CurrentContext.cert.internal.webclient) {CurrentContext.cert.internal.webclient = {}}
            key_id = CurrentContext.cert.internal.webclient.key_id = CurrentContext.metaData.webinosName + "_webclient";
        } else if (type === "PzhSSL") {
            if(!CurrentContext.cert.internal.webssl) {CurrentContext.cert.internal.webssl = {}}
            key_id = CurrentContext.cert.internal.webssl.key_id = CurrentContext.metaData.webinosName + "_webssl";
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
                CurrentContext.cert.internal.signedCert = {};
                CurrentContext.cert.internal.revokedCert = {};
            } else if (type === "PzpCA") {
                CurrentContext.cert.internal.pzh = {}
            }
            cn = encodeURIComponent(cn);

            if (cn.length > 40) {
                cn = cn.substring (0, 40);
            }
            getCertificateManager(function(status, certificateManager) {
                if (status) {
                    CurrentContext.generateStoreKey(type, key_id, function (status, privateKey) {
                        if (!status) {
                            return callback (false, privateKey); // This has already error set by keyStore
                        } else {
                            logger.log (type + " created private key (certificate generation I step)");
                            try {
                                obj.csr = certificateManager.createCertificateRequest (privateKey,
                                    encodeURIComponent (CurrentContext.userData.country),
                                    encodeURIComponent (CurrentContext.userData.state), // state
                                    encodeURIComponent (CurrentContext.userData.city), //city
                                    encodeURIComponent (CurrentContext.userData.orgname), //orgname
                                    encodeURIComponent (CurrentContext.userData.orgunit), //orgunit
                                    cn,
                                    encodeURIComponent (CurrentContext.userData.email));
                                if (!obj.csr) throw "userData is empty";
                            } catch (err) {
                                callback (false, {"Component": "CertificateManager","Type": "FUNC_ERROR", "Error": err,
                                    "Message": "failed generating CSR. user details are missing"});
                                return;
                            }

                            try {
                                logger.log (type + " generated CSR (certificate generation II step)");
                                var serverName;
                                if (require("net").isIP(CurrentContext.metaData.serverName)) {
                                    serverName = "IP:" + CurrentContext.metaData.serverName;
                                } else {
                                    serverName = "DNS:" + CurrentContext.metaData.serverName;
                                }
                                obj.cert = certificateManager.selfSignRequest (obj.csr, 3600, privateKey, cert_type, serverName);
                            } catch (e1) {
                                return callback (false, {"Component": "CertificateManager","Type": "FUNC_ERROR", "Error": e1,
                                    "Message": "failed self signing certificate"});
                            }
                            logger.log (type + " generated self signed certificate (certificate generation III step)");
                            if (type === "PzhPCA" || type === "PzhCA" || type === "PzpCA") {
                                CurrentContext.cert.internal.master.cert = obj.cert;
                                try {
                                    obj.crl = certificateManager.createEmptyCRL (privateKey, obj.cert, 3600, 0);
                                } catch (e2) {
                                    return callback (false, {"Component": "CertificateManager","Type": "FUNC_ERROR", "Error": e2,
                                        "Message": "failed generating crl"});
                                }
                                logger.log (type + " generated crl (certificate generation IV step)");
                                CurrentContext.crl.value = obj.crl;
                                if (type === "PzpCA") { CurrentContext.cert.internal.master.csr = obj.csr;} // We need to get it signed by PZH during PZP enrollment
                                return callback(true);
                            } else if (type === "PzhP" || type === "Pzh" || type === "Pzp") {
                                CurrentContext.cert.internal.conn.cert = obj.cert;
                                if (type === "Pzp") { CurrentContext.cert.internal.conn.csr = obj.csr; }
                                return callback (true, obj.csr);
                            }  else if (type === "PzhWS" || type === "PzhSSL") {
                                return callback (true, obj.csr);
                            }
                        }
                    });
                } else {
                    callback(false, certificateManager);// This is error from getCertificateManager call
                }
            });
        } catch (err) {
            callback(false, {"Component": "CertificateManager","Type": "EXCEPTION", "Error": err,
                             "Message": "certificate parameters are missing"});
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
                    console.log(CurrentContext.cert.internal.master.key_id)
                    CurrentContext.fetchKey(CurrentContext.cert.internal.master.key_id, function (status, privateKey) {
                        if (status) {
                            var server,  clientCert;
                            if (require ("net").isIP (CurrentContext.metaData.serverName)) {
                                server = "IP:" + CurrentContext.metaData.serverName;
                            } else {
                                server = "DNS:" + CurrentContext.metaData.serverName;
                            }
                            clientCert = certificateManager.signRequest (csr, 3600, privateKey,
                                            CurrentContext.cert.internal.master.cert, certificateType.CLIENT, server);
                            logger.log ("signed certificate by the PZP/PZH");
                            callback (true, clientCert);
                        } else {
                            callback (false, privateKey); // It is not privateKey but an error returned by fetchKey
                        }
                    });
                } else {
                    callback (false, certificateManager);// Value is set by getCertificateManager call
                }
            });
        } catch (err) {
            callback (false, {"Component": "CertificateManager","Type": "EXCEPTION", "Error": err,
                "Message": "certificate signing error"});
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
                } else {
                    callback(false, certificateManager); // This is error from getCertificateManager cal
                }
            });
        } catch (err) {
            callback(false, {"Component": "CertificateManager","Type": "EXCEPTION", "Error": err,
                "Message": "getKeyHash failed"});
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
                    CurrentContext.fetchKey(CurrentContext.cert.internal.master.key_id, function (status, value) {
                        if (status) {
                            var crl = certificateManager.addToCRL ("" + value, "" + CurrentContext.crl.value, "" + pzpCert);
                            // master.key.value, master.cert.value
                            logger.log("revoked certificate");
                             callback (true, crl);
                        } else {
                            callback (false, value)
                        }
                    });
                } else {
                    callback (false, certificateManager);// Value is set by getCertificateManager call
                }
            });
        } catch (err) {
            callback (false, {"Component": "CertificateManager","Type": "EXCEPTION", "Error": err,
                "Message": "certificate revoke error"});
        }
    };
};
require("util").inherits(Certificate, KeyStore);
module.exports = Certificate;
