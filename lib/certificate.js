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
var Certificate = function(webinosMetaData) {
    "use strict";
    Certificate.prototype.__proto__ = require("events").EventEmitter.prototype;
    var CertContext=this, certificateType, certificateManager, logger, KeyStore;
    function checkDependencies(){
        try{
            KeyStore = require("webinos-keyStorage");
            logger   = require("webinos-utilities").webinosLogging(__filename);
        } catch(err) {
            CertContext.emit("MODULE_MISSING", new Error("Required Webinos Modules are Missing "+ err));
            return undefined;
        }
        try {
            certificateManager = require ("certificate_manager");
        } catch(err){
            CertContext.emit("MODULE_MISSING", new Error("Certificate manager compiled module is missing." +
                "run node-gyp configure build to trigger certificate manager build and try again - "+ err));
            return undefined;
        }
        if (typeof webinosMetaData !== "object" && webinosMetaData!==[] 
            && !webinosMetaData.webinosRoot && !webinosMetaData.webinosType
            && !webinosType.serverName && !webinosType.webinosName) {
            CertContext.emit("PARAMS_MISSING", new Error("Webinos MetaData is not correct, certificate manager cannot generate" +
                " certificates. Possible reason is webinos configuration is corrupted - "+ err));
            return undefined;
        }

        if (!(CertContext.userData = (require("webinos-utilities").loadConfig(require("path").join(__dirname, "../", "config.json"))))){
            CertContext.emit("PARAMS_MISSING", new Error("Webinos params are missing - "+ err));
            return undefined;
        }
        return CertContext;
    }

    function initializeErrorHandlers(){
        // All these exceptions are also handled in PZP
        CertContext.on("MODULE_MISSING", function(errMsg){
            logger.log("Module loading failed as require module is missing. - "+ errMsg);
        });
        CertContext.on("PARAMS_MISSING", function(errMsg){
            logger.log("Required parameters are missing - "+ errMsg);
        });
        CertContext.on("EXCEPTION", function(errMsg){
            logger.log("Encountered an exception - " +errMsg);
        });
        CertContext.on("FUNC_ERROR", function(errMsg){
            logger.log("Encountered a functionality error - "+ errMsg);
        });
    }
    function initializeCertificate() {
        CertContext.webinosMetaData= {};
        for (var key in webinosMetaData) {
            CertContext.webinosMetaData[key] = webinosMetaData[key];
        }
        CertContext.internal={master:{}, conn:{}, web:{}};
        CertContext.external={};
        CertContext.crl = {};
        certificateType = Object.freeze({ "SERVER": 0, "CLIENT": 1});
        initializeErrorHandlers();
        checkDependencies();
        CertContext.userData = CertContext.userData.params;
        CertContext.keyStore = new KeyStore(CertContext.webinosMetaData.webinosType, CertContext.webinosMetaData.webinosRoot);
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
            key_id = CertContext.internal.master.key_id = CertContext.webinosMetaData.webinosName + "_master";
        } else if (type === "PzhP" || type === "Pzh" || type === "Pzp") {
            key_id = CertContext.internal.conn.key_id = CertContext.webinosMetaData.webinosName + "_conn";
        } else if (type === "PzhWS") {
            if(!CertContext.internal.webclient) {CertContext.internal.webclient = {}}
            key_id = CertContext.internal.webclient.key_id = CertContext.webinosMetaData.webinosName + "_webclient";
        } else if (type === "PzhSSL") {
            if(!CertContext.internal.webssl) {CertContext.internal.webssl = {}}
            key_id = CertContext.internal.webssl.key_id = CertContext.webinosMetaData.webinosName + "_webssl";
        }
        return key_id;
    }

    function generatePrivateKey(type) {
        var key;
        try {
            if (type === "PzhPCA" ||  type === "PzhCA" || type === "PzpCA"){
                key = certificateManager.genRsaKey(2048);
            } else {
                key = certificateManager.genRsaKey(1024);
            }
            CertContext.keyStore.storeKey(getKeyId(type), key);
            return key;
        }catch(err) {
            CertContext.emit("FUNC_ERROR", new Error("Failed Generating Private Key - "+ err));
        }
        return undefined;
    }

    function generateCSR(cn, privateKey) {
        try {
            cn = (encodeURIComponent(cn)).substring (0, 40);
            var csr = certificateManager.createCertificateRequest (privateKey,
                encodeURIComponent(CertContext.userData.country),
                encodeURIComponent(CertContext.userData.state), // state
                encodeURIComponent(CertContext.userData.city), //city
                encodeURIComponent(CertContext.userData.orgname), //orgname
                encodeURIComponent(CertContext.userData.orgunit), //orgunit
                cn,
                encodeURIComponent(CertContext.userData.email));
            if (!csr) throw "userData is empty or incorrect";
            return csr;
        } catch (err) {
            CertContext.emit("FUNC_ERROR", new Error("Failed Generating CSR. - "+err));
        }
        return undefined;
    }

    function generateSelfSignedCert(type, privateKey, csr) {
        try {
            var server, cert;
            server = (require ("net").isIP(CertContext.webinosMetaData.serverName))? "IP:" : "DNS:";
            server += CertContext.webinosMetaData.serverName;          
            cert = certificateManager.selfSignRequest (csr, 18000, privateKey, getCertType(type), server);
            return cert;
        } catch (err) {
            CertContext.emit("FUNC_ERROR", new Error("Failed Self-Signing Certificate - "+err));
        }
        return undefined;
    }

    function generateCRL(privateKey, cert) {
        try {
            return certificateManager.createEmptyCRL (privateKey, cert, 18000, 0);
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
     *
     */
    this.generateSelfSignedCertificate = function (type, cn) {
        try {
            var privateKey, csr, cert, crl;
            CertContext.internal.signedCert = {};
            CertContext.internal.revokedCert = {};
            if (type === "PzpCA") {
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
                                CertContext.crl.value = crl;
                                // We need to get it signed by PZH during PZP enrollment
                                if (type === "PzpCA")  CertContext.internal.master.csr = csr;
                                return true;
                            }
                        } else if (type === "PzhP" || type === "Pzh" || type === "Pzp") {
                            CertContext.internal.conn.cert = cert;
                            if (type === "Pzp") CertContext.internal.conn.csr = csr;
                            return csr;
                        }  else if (type === "PzhWS" || type === "PzhSSL") {
                            return csr;
                        }
                    }
                }
            }
        } catch (err) {
            CertContext.emit("EXCEPTION", new Error("Failed Creating Certificates - "+ err));
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
            var privateKey;
            if((privateKey = CertContext.keyStore.fetchKey(CertContext.internal.master.key_id))){
                var server,  clientCert;
                server = (require ("net").isIP(CertContext.webinosMetaData.serverName))? "IP:" : "DNS:";
                server += CertContext.webinosMetaData.serverName;
                try {
                    clientCert = certificateManager.signRequest (csr, 18000, privateKey,
                        CertContext.internal.master.cert, certificateType.CLIENT, server);
                    logger.log ("Signed Certificate by the PZP/PZH");
                    return clientCert;
                } catch (err) {
                    CertContext.emit("FUNC_ERROR", new Error("Failed Signing Client Certificate - "+err.messsage));
                    return undefined;
                }
            }
        } catch (err) {
            CertContext.emit("EXCEPTION", new Error("Signing Certificate Generated Error - "+err));
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
            var hash = certificateManager.getHash(certPath);
            logger.log("Key Hash is" + hash);
            return hash;
        } catch (err) {
            CertContext.emit("EXCEPTION", new Error("GetKey Hash Failed - "+err));
            return undefined;
        }
    };

    /**
     * Revokes a PZP certificate. Revoke functionality is intended to be run only by a Server
     * @param {String} pzpCert - PEM formatted string that needs to be revoked
     */
    this.revokeClientCert = function (pzpCert) {
        try {
            var privateKey;
            if ((privateKey = CertContext.keyStore.fetchKey(CertContext.internal.master.key_id))) {
                try {
                    var crl = certificateManager.addToCRL ("" +privateKey, "" + CertContext.crl.value, "" + pzpCert); // master.key.value, master.cert.value
                    logger.log("revoked certificate");
                    return crl;
                } catch(err){
                    CertContext.emit("FUNC_ERROR", new Error("Certificate Revoke Failed - "+ err));
                    return undefined;
                }
            }
        } catch (err) {
            CertContext.emit("EXCEPTION", new Error("Certificate Revoke Failed - " + err));
            return undefined;
        }
    };
    this.parseCert = function(cert, format){
        var convType = (format === "base64") ? 2 : 1;
        var parseCert =  certificateManager.parseCert(cert, convType);
        var list = parseCert && parseCert.subject  && parseCert.subject.split("/"), value={};
        if (list) {
            list.forEach(function(name){
                var tmp = name && name.split("=");
                if (tmp) value[tmp[0]] = decodeURIComponent(tmp[1]);
            });
        }
        parseCert.subject = value;
        var list1 = parseCert && parseCert.issuer  && parseCert.issuer.split("/"), value1={};
        if(list1){
            list1.forEach(function(name){
                var tmp = name && name.split("=");
                if(tmp) value1[tmp[0]] = decodeURIComponent(tmp[1]);
            });
        }

        parseCert.issuer = value1;
        return parseCert;
    };
    this.parseCrl = function(crl, format){
        var convType = (format === "base64") ? 2 : 1;
        var parseCrl =  certificateManager.parseCrl(crl, convType);
        var list1 = parseCrl && parseCrl.issuer  && parseCrl.issuer.split("/"), value1={};
        list1.forEach(function(name){
            var tmp = name && name.split("=");
            if(tmp) value1[tmp[0]] = decodeURIComponent(tmp[1]);
        });
        parseCrl.issuer = value1;
        return parseCrl;
    };

    this.validateConnection = function(connIssuer, caCert, crlCert) {
        var status = false, tmp, conn, tmp1 = decodeURIComponent(connIssuer), parseCACert = {};

        for (var i = 0 ; i < caCert.length; i = i + 1) {
            tmp = CertContext.parseCert(caCert[i], "pem");
            if (tmp1 === tmp.subject.CN) conn = caCert[i];
            parseCACert[tmp.subject.CN] = tmp;
        }
        if (conn) {
            var parseCert = CertContext.parseCert(conn, "pem");
            if (parseCert) {
                status = (certificateManager.verifyCertificate(conn, caCert) && parseCACert.hasOwnProperty(parseCert.issuer.CN));
            }
        }
        return status;
    };

    this.validateCertificateChain = function(chain, caCertificates){
        var result = false;
        if(!chain || chain.length < 1)
           return result;
        for(var i = 0, j = i+1; i < chain.length && j < chain.length; i++){
            var cert =   this.parseCert(chain[i], "pem");
            var issuer =   this.parseCert(chain[j], "pem");
            if(cert.issuer.CN !== issuer.subject.CN){
                //Chain is invalid
                return result;
            }
        }
        var root =  this.parseCert(chain[chain.length - 1], "pem");
        if(root){
            result = this.validateConnection(root.issuer.CN, caCertificates);
        }
        return result;
    }
    initializeCertificate();
};
module.exports = Certificate;
