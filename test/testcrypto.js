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

var certman = require('certificate_manager');
var path = require("path");
var debug = true;
var caKey = certman.genRsaKey(2048);
if (debug) console.log("CA Master Key \n[" + caKey + "]\n");

var caCertReq = certman.createCertificateRequest(caKey,
    "UK","OX","Oxford","Univ. Oxford","Computer Science", "Johns PZH CA", "john.lyle@cs.ox.ac.uk");
if (debug) console.log("PZH CA Certificate Request: \n[" + caCertReq + "]\n");

var caCert = certman.selfSignRequest(caCertReq, 30, caKey, 0 ,"URI:http://test.url");
if (debug) console.log("PZH CA Certificate: \n[" + caCert + "]\n");


var crl = certman.createEmptyCRL(caKey, caCert, 30, 0);
if (debug) console.log("PZH CRL: \n[" + crl + "]\n");

var pzpKey = certman.genRsaKey(1024);
if (debug) console.log("PZP Master Key \n[" + pzpKey + "]\n");

var pzpCertReq = certman.createCertificateRequest(pzpKey,
    "UK","OX","Oxford","Univ. Oxford","Computer Science", "Johns PZP", "john.lyle@cs.ox.ac.uk");
if (debug) console.log("PZP Certificate Request: \n[" + pzpCertReq + "]\n");

var pzpCert = certman.signRequest(pzpCertReq, 30, caKey, caCert, 1, "URI:http://test.url");
if (debug) console.log("PZP Certificate, signed by PZH CA: \n[" + pzpCert + "]\n");


var crlWithKey = certman.addToCRL(caKey, crl, pzpCert);
if (debug) console.log("PZP Certificate revoked, new CRL: \n[" + crlWithKey + "]\n");


var cert_path = path.join(__dirname, "conn.pem");
//var data = require("fs").readFileSync(cert_path, "utf8")
var hash = certman.getHash(cert_path);
console.log("PZP public hash key, hash: \n[" + hash + "]\n");

var certPath  = path.join(__dirname, "conn.pem");
var data = require("fs").readFileSync(certPath)
console.log(certman.parseCert(data.toString(), 1));

certPath  = path.join(__dirname, "base64_cert");
data = require("fs").readFileSync(certPath)
console.log(certman.parseCert(data.toString(), 2));

var crlPath  = path.join(__dirname, "crl.pem");
var data1 = require("fs").readFileSync(crlPath)
console.log(certman.parseCrl(data1.toString(), 1));

//var parseCert = certman.parseCert(data.toString());
//console.log(" \n[ certificate data " + parseCert + "]\n");

 




