package jten.mil

import grails.core.GrailsApplication
import grails.gorm.transactions.Transactional
import groovy.json.JsonSlurper
import org.apache.commons.validator.routines.InetAddressValidator
import org.apache.hc.client5.http.classic.methods.HttpGet
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager
import org.apache.hc.client5.http.protocol.HttpClientContext
import org.apache.hc.client5.http.socket.ConnectionSocketFactory
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory
import org.apache.hc.core5.http.config.Registry
import org.apache.hc.core5.http.config.RegistryBuilder
import org.apache.hc.core5.http.io.entity.EntityUtils
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.TrustManager
import javax.net.ssl.X509ExtendedTrustManager
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate

class LookupService {
    GrailsApplication grailsApplication
    def asset2Service

    //for each asset in Assets, update name information based on Infoblox retrieval
    @Transactional
    def getName() {
        List<Asset> assetList = Asset.list()
        SSLContext sslContext = getSslContext()
        for (asset in assetList) {
            if (asset.ipAddress != 'None') {
                String uri = grailsApplication.config.getProperty('infobloxUrl', String.class) + "ipv4address?ip_address=${asset.ipAddress}"
                String auth = "Basic " + grailsApplication.config.getProperty('infobloxEncodedNamePassword', String.class)
                String json = ""
                Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory> create()
                        .register("https", new SSLConnectionSocketFactory(sslContext))
                        .build()
                CloseableHttpClient httpClient = HttpClientBuilder.create()
                        .setConnectionManager(new PoolingHttpClientConnectionManager(registry))
                        .build()
                try {
                    HttpGet httpGet = new HttpGet(uri)
                    httpGet.addHeader("Authorization", auth)
                    httpGet.addHeader("Content-Type", "application/json")
                    HttpClientContext clientContext = HttpClientContext.create()
                    httpClient.execute(httpGet, clientContext, response -> {
                        json = EntityUtils.toString(response.getEntity())
                    })
                } catch (e) {
                    log.error("Infoblox lookup error.")
                    log.error("Error: " + e.getMessage())
                }
                finally {
                    httpClient.close()
                }

                if (json) {
                    List<String> objects
                    def jsonSlurper = new JsonSlurper()
                    def json1 = jsonSlurper.parseText(json)
                    //get "objects" entries
                    try {
                        objects = json1.objects
                        if (asset.ipAddress != "None") {
                            def domainControllers = grailsApplication.config.getProperty('domainControllers', String.class)
                            //check for domain controllers entries
                            if (domainControllers) {
                                def domainControllers1 = domainControllers.split(",")
                                //checking to see if domain controllers list contains asset ip address
                                // if it does, do not update domain controller name
                                if (!domainControllers1.contains(asset.ipAddress)) {
                                    def objectMatch = false
                                    String[] objects2 = []
                                    Boolean hostRecord = false
                                    Boolean aRecord = false
                                    for (object in objects[0]) {
                                        //use host records only
                                        //parsing host record entries in Infoblox to get proper name for asset
                                        def object4 = ""
                                        if (!objectMatch) {
                                            if (object.startsWith('record:host')) {
                                                if (!hostRecord) {
                                                    hostRecord = true
                                                    //split a 2nd ":"
                                                    String[] object1 = object.split("/")
                                                    //split at "/"
                                                    objects2 = object1[1].split(":")
                                                    object4 = objects2[1]
                                                    //use 2nd part of array to get host record
                                                    if (object4 == asset.name) {
                                                        objectMatch = true
                                                    }
                                                }
                                                if (!objectMatch) {
                                                    if (object4) {
                                                        //Check to see if the asset name is already in use
                                                        def asset1 = Asset.findWhere(name: object4)
                                                        if (asset1) {
                                                            asset1.name = "temp_" + System.currentTimeMillis()
                                                            asset1.save(flush: true)
                                                        }
                                                        log.warn("Assigning from Host Record ${object4} to Asset with Current Name ${asset.name} and with IP Address ${asset.ipAddress}")
                                                        log.warn("----------------------------------------")
                                                        asset.name = object4
                                                        asset.save(flush: true)
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    if (!hostRecord) {
                                        for (objectEntry in objects[0]) {
                                            //use alias records only
                                            if (objectEntry.startsWith('record:a')) {
                                                objects2 += objectEntry
                                                aRecord = true
                                            }
                                        }
                                        if (objects2.size() > 0) {
                                            String object4 = ""
                                            for (entry in objects2) {
                                                if (!objectMatch) {
                                                    //split a 2nd ":"
                                                    String[] object1 = entry.split("/")
                                                    //split at "/"
                                                    objects2 = object1[1].split(":")
                                                    //use 2nd part of array to get alias record
                                                    object4 = objects2[1]
                                                    if (object4 == asset.name) {
                                                        objectMatch = true
                                                    }
                                                }
                                            }
                                            if (!objectMatch) {
                                                //Check to see if the asset name is already in use
                                                def asset1 = Asset.findWhere(name: object4)
                                                if (asset1) {
                                                    asset1.name = "temp_" + System.currentTimeMillis()
                                                    asset1.save(flush: true)
                                                }
                                                log.warn("Assigning from A record ${object4} to asset with current name ${asset.name} and ip address ${asset.ipAddress}")
                                                log.warn("--------------------------------------------------------")
                                                asset.name = object4
                                                asset.save(flush: true)
                                            }
                                        }
                                    }
                                    if (!aRecord && !hostRecord) {
                                        log.warn("No A Record or Host Record found.  Deleting asset: ${asset.ipAddress}")
                                        asset2Service.assetRemove(asset)
                                    }
                                }
                            } else {
                                log.error("No Domain Controllers entries.")
                            }
                        }
                    } catch (e) {
                        e.suppressed
                        if (objects) {
                            log.error("Objects: " + objects)
                        } else {
                            log.error("No objects")
                        }
                        log.warn("No DNS entry for ip address ${asset.ipAddress} matches asset name: ${asset.name}.  Deleting asset entry.")
                        asset2Service.deleteAsset(asset.id)
                    }
                }
            }
        }
        getName2()
    }

    //check a specific hostname, ipAddress by performing an Infoblox lookup
    def getName1(String hostname, String ipAddress) {
        if (InetAddressValidator.getInstance().isValidInet4Address(ipAddress)) {
            def useAssetNameMap = ["assetName": hostname]
            Map<String, Boolean> createAssetMap = ["createAsset": false]
            String uri = grailsApplication.config.getProperty('infobloxUrl', String.class) + "ipv4address?ip_address=${ipAddress}"
            String auth = "Basic " + grailsApplication.config.getProperty('infobloxEncodedNamePassword', String.class)
            String json = ''
            SSLContext sslContext = getSslContext()
            Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory> create()
                    .register("https", new SSLConnectionSocketFactory(sslContext))
                    .build()
            CloseableHttpClient httpClient = HttpClientBuilder.create()
                    .setConnectionManager(new PoolingHttpClientConnectionManager(registry))
                    .build()
            try {
                HttpGet httpGet = new HttpGet(uri)
                httpGet.addHeader("Authorization", auth)
                httpGet.addHeader("Content-Type", "application/json")
                HttpClientContext clientContext = HttpClientContext.create()
                httpClient.execute(httpGet, clientContext, response -> {
                    json = EntityUtils.toString(response.getEntity())
                })
            } catch (e) {
                log.error("Infoblox lookup error.")
                log.error("Error: " + e.getMessage())
            }
            finally {
                httpClient.close()
            }
            if (json) {
                def jsonSlurper = new JsonSlurper()
                def json1 = jsonSlurper.parseText(json)
                //get "objects" entries
                def objectList = []
                try {
                    objectList = json1.objects[0]
                    //if objects exist
                    if (objectList!= null) {
                        def object2
                        //if there are objects
                        if (objectList.size() > 0) {
                            Boolean recordA = false
                            Boolean hostnameMatch = false
                            for (objectEntry in objectList) {
                                //use alias records only
                                //if a hostname match does not exist
                                if (hostnameMatch != true) {
                                    if (objectEntry.startsWith('record:a')) {
                                        recordA = true
                                        //split at 2nd ":"
                                        String objectEntryString = objectEntry.toString()
                                        def object1 = objectEntryString.split(":")
                                        //split at "/"
                                        object2 = object1[2].split("/")
                                        //use first part of array to get alias record
                                        //if object2[0] equals host name, then continue to use hostname
                                        if (object2[0] == hostname) {
                                            createAssetMap = ["createAsset": true]
                                            useAssetNameMap = ["assetName": hostname]
                                            hostnameMatch = true
                                            //update asset name to object2[0]
                                        } else {
                                            createAssetMap = ["createAsset": true]
                                            useAssetNameMap = ["assetName": object2[0]]
                                            hostnameMatch = true
                                        }
                                    }
                                }
                            }
                            if (!recordA) {
                                for (objectEntry in objectList) {
                                    //use alias records only
                                    if (!hostnameMatch) {
                                        if (objectEntry.startsWith('record:host')) {
                                            //split a 2nd ":"
                                            String objectEntryString = objectEntry.toString()
                                            String[] object1 = objectEntryString.split(":")
                                            //split at "/"
                                            object2 = object1[2].split("/")
                                            //use first part of array to get alias record
                                            if (object2[0] == hostname) {
                                                createAssetMap = ["createAsset": true]
                                                useAssetNameMap = ["assetName": hostname]
                                                hostnameMatch = true
                                            } else {
                                                createAssetMap = ["createAsset": true]
                                                useAssetNameMap = ["assetName": object2[0]]
                                                hostnameMatch = true
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                catch (e) {
                    e.getSuppressed()
                    //log.error("Asset with IP Address: ${ipAddress} has no object entries")
                    createAssetMap = ["createAsset": false]
                    useAssetNameMap = ["assetName": "None"]
                }
            }
            return (createAssetMap + useAssetNameMap)
        } else {
            //log.error ("Not IPv4 address")
            def createAssetMap = ["createAsset": false]
            def useAssetNameMap = ["assetName": "None"]
            return (createAssetMap + useAssetNameMap)
        }
    }

    //for each asset that begins with "temp_" in Assets, update name information based on Infoblox retrieval
    @Transactional
    def getName2() {
        List<Asset> assetList = Asset.list()
        SSLContext sslContext = getSslContext()
        for (asset in assetList) {
            if (asset.name.startsWith("temp_")) {
                String uri = grailsApplication.config.getProperty('infobloxUrl', String.class) + "ipv4address?ip_address=${asset.ipAddress}"
                String auth = "Basic " + grailsApplication.config.getProperty('infobloxEncodedNamePassword', String.class)
                String json = ""
                Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory> create()
                        .register("https", new SSLConnectionSocketFactory(sslContext))
                        .build()
                CloseableHttpClient httpClient = HttpClientBuilder.create()
                        .setConnectionManager(new PoolingHttpClientConnectionManager(registry))
                        .build()
                try {
                    HttpGet httpGet = new HttpGet(uri)
                    httpGet.addHeader("Authorization", auth)
                    httpGet.addHeader("Content-Type", "application/json")
                    HttpClientContext clientContext = HttpClientContext.create()
                    httpClient.execute(httpGet, clientContext, response -> {
                        json = EntityUtils.toString(response.getEntity())
                    })
                } catch (e) {
                    log.error("Infoblox lookup error.")
                    log.error("Error: " + e.getMessage())
                }
                finally {
                    httpClient.close()
                }
                if (json) {
                    List<String> objects
                    def jsonSlurper = new JsonSlurper()
                    def json1 = jsonSlurper.parseText(json)
                    //get "objects" entries
                    try {
                        objects = json1.objects
                        def domainControllers = grailsApplication.config.getProperty('domainControllers', String.class)
                        def domainControllers1 = domainControllers.split(",")
                        if (!domainControllers1.contains(asset.ipAddress)) {
                            def objectMatch = false
                            String[] objects2 = []
                            Boolean hostRecord = false
                            Boolean aRecord = false
                            for (object in objects[0]) {
                                //use host records only
                                def object4 = ""
                                if (!objectMatch) {
                                    if (object.startsWith('record:host')) {
                                        if (!hostRecord) {
                                            hostRecord = true
                                            //split a 2nd ":"
                                            String[] object1 = object.split("/")
                                            //split at "/"
                                            objects2 = object1[1].split(":")
                                            object4 = objects2[1]
                                            //use 2nd part of array to get host record
                                            if (object4 == asset.name) {
                                                objectMatch = true
                                            }
                                        }
                                        if (!objectMatch) {
                                            if (object4) {
                                                log.warn("Host Record: " + object4)
                                                log.warn("Assigning from Host Record ${object4} to Asset with Current Name ${asset.name} and IP Address ${asset.ipAddress}")
                                                log.warn("----------------------------------------")
                                                asset.name = object4
                                                asset.save(flush:true)
                                            }
                                        }
                                    }
                                }
                            }
                            if (!hostRecord) {
                                for (objectEntry in objects[0]) {
                                    //use alias records only
                                    if (objectEntry.startsWith('record:a')) {
                                        objects2 += objectEntry
                                        aRecord = true
                                    }
                                }
                                if (objects2.size() > 0) {
                                    String object4 = ""
                                    for (entry in objects2) {
                                        if (!objectMatch) {
                                            //split a 2nd ":"
                                            String[] object1 = entry.split("/")
                                            //split at "/"
                                            objects2 = object1[1].split(":")
                                            //use 2nd part of array to get alias record
                                            object4 = objects2[1]
                                            if (object4 == asset.name) {
                                                objectMatch = true
                                            }
                                        }
                                    }
                                    if (!objectMatch) {
                                        log.warn("A Record: ${object4}")
                                        log.warn("Assigning from A Record Entry to Asset with Current Name ${asset.name} and IP Address ${asset.ipAddress}")
                                        log.warn("--------------------------------------------------------")
                                        asset.name = object4
                                        asset.save(flush:true)
                                    }
                                }
                            }
                        }
                    } catch (e) {
                        e.suppressed
                    }
                }
            }
        }
    }

    //check all records for IP address
    def getAssetDns (String id) {
        Long idLong = Long.valueOf(id)
        Asset asset = Asset.findWhere(id: idLong)
        log.warn ( "Asset: ${asset.name}")
        def total = []
        String uri = grailsApplication.config.getProperty('infobloxUrl', String.class) + "ipv4address?ip_address=${asset.ipAddress}"
        String auth = "Basic " + grailsApplication.config.getProperty('infobloxEncodedNamePassword', String.class)
        String json = ''
        SSLContext sslContext = getSslContext()
        Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory> create()
                .register("https", new SSLConnectionSocketFactory(sslContext))
                .build()
        CloseableHttpClient httpClient = HttpClientBuilder.create()
                .setConnectionManager(new PoolingHttpClientConnectionManager(registry))
                .build()
        try {
            HttpGet httpGet = new HttpGet(uri)
            httpGet.addHeader("Authorization", auth)
            httpGet.addHeader("Content-Type", "application/json")
            HttpClientContext clientContext = HttpClientContext.create()
            httpClient.execute(httpGet, clientContext, response -> {
                json = EntityUtils.toString(response.getEntity())
            })
        } catch (e) {
            log.error("Infoblox lookup error.")
            log.error("Error: " + e.getMessage())
        }
        finally {
            httpClient.close()
        }
        if (json) {
            def jsonSlurper = new JsonSlurper()
            def json1 = jsonSlurper.parseText(json)
            //get "objects" entries
            def objectList

            try {
                objectList = json1.objects[0]
                log.warn ( "Object List: " + objectList)
                //if objects exist
                if (objectList != [null]) {
                    String[] object2
                    //if there are objects
                    if (objectList.size() != 0) {
                        Map typeMap
                        Map valueMap
                        def id1 = 0
                        for (objectEntry in objectList) {
                            String objectEntryString = objectEntry.toString()
                            String[] object1 = objectEntryString.split(":")
                            if (object1[0].startsWith ("fixedaddress")) {
                                typeMap = ["type": "Reservation"]
                                def value1 = object1[1]
                                def value2 = value1.split("/")
                                valueMap = ["value": value2[0]]
                            } else if (object1[0].startsWith ("lease")){
                                typeMap = ["type": "Lease"]
                                def value1 = object1[1]
                                def value2 = value1.split("/")
                                valueMap = ["value": value2[0]]
                            } else if (object1[1].startsWith ("a")) {
                                typeMap = ["type": "Alias"]
                                def value1 = object1[2]
                                def value2 = value1.split("/")
                                valueMap = ["value": value2[0]]
                            } else if (object1[1].startsWith ("host")) {
                                typeMap = ["type": "Host"]
                                def value1 = object1[2]
                                def value2 = value1.split("/")
                                valueMap = ["value": value2[0]]
                            } else if (object1[1].startsWith ("ptr")) {
                                typeMap = ["type": "Pointer"]
                                def value1 = object1[2]
                                def value2 = value1.split("/")
                                valueMap = ["value": value2[0]]
                            } else {
                                typeMap = ["type": "Unknown"]
                                valueMap = ["value": "Check Infoblox"]
                            }
                            Map idMap = ["id": id1]
                            id1 += 1
                            total += idMap + typeMap + valueMap
                        }
                    }
                }
            }
            catch (e) {
                e.suppressed
                log.error("Asset with IP Address: ${asset.ipAddress} and name: ${asset.name} has no object entries")
                total = ["type": "None"] + ["assetName": "None"]
            }
        }
        log.warn ("Total: " + total)
        return total
    }

    def getSslContext() {
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509ExtendedTrustManager() {

                    @Override
                    void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {

                    }

                    @Override
                    void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {

                    }

                    @Override
                    void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {

                    }

                    @Override
                    void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {

                    }

                    @Override
                    void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {

                    }

                    @Override
                    void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {

                    }

                    @Override
                    X509Certificate[] getAcceptedIssuers() {
                        //return null
                        return new X509Certificate[0]
                    }
                }
        }
        SSLContext sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, trustAllCerts, new SecureRandom())
        return sslContext
    }
}