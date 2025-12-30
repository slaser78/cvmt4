package jten.mil

import grails.gorm.transactions.Transactional
import groovy.json.JsonSlurper
import org.apache.hc.client5.http.classic.methods.HttpGet
import org.apache.hc.client5.http.classic.methods.HttpPost
import org.apache.hc.client5.http.protocol.HttpClientContext
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient
import org.apache.hc.client5.http.impl.classic.HttpClients
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder
import org.apache.hc.core5.ssl.SSLContexts
import org.apache.hc.core5.http.io.entity.EntityUtils
import org.apache.hc.core5.http.io.entity.StringEntity
import javax.net.ssl.SSLContext
import grails.core.GrailsApplication

class AssetService {
    def lookupService
    GrailsApplication grailsApplication

    //Upload assets from CSV
    def uploadAsset(def fileData) {
        String file = new String(fileData, "UTF-8")
        ArrayList rows = file.readLines().tail()*.split(',')
        int total = rows.size()
        ArrayList name = rows*.getAt(0)
        ArrayList ipAddress = rows*.getAt(1)
        ArrayList description = rows*.getAt(2)
        ArrayList aor = rows*.getAt(3)
        ArrayList poc = rows*.getAt(4)
        ArrayList crit = rows*.getAt(5)
        ArrayList por = rows*.getAt(6)
        for (def i = 0; i < total; i++) {
            Asset asset = Asset.findWhere(ipAddress: ipAddress[i])
            if (asset) {
                asset.name = name[i]
                if (description[i]) {
                    asset.description = description[i]
                } else {
                    asset.description = "NA"
                }
                String aorString = aor[i]
                Aor aorInstance = Aor.findWhere(name: aorString)
                asset.aor = aorInstance
                String pocString = poc[i]
                Poc pocInstance = Poc.findWhere(name: pocString)
                asset.poc = pocInstance
                asset.ipAddress = ipAddress[i]
                if (crit[i] == "no") {
                    asset.crit = false
                } else {
                    asset.crit = true
                }
                if (por[i] == "no") {
                    asset.por = false
                } else {
                    asset.por = true
                }
                try {
                    asset.save()
                } catch (e) {
                    e.getMessage()
                }
            }
        }
    }

//Get assets from ACAS
    @Transactional
    def getAssets(Map map) {
        String token = "${map.get("token")}"
        String cookie = "${map.get("cookie")}"
        if (cookie != "null") {
            ArrayList<String> assetList1 = []
            SSLContext sslContext = lookupService.getSslContext()
            //create a list of asset IP addresses
            def assetList = Asset.findAll()
            if (assetList) {
                for (asset in assetList) {
                    if (asset.ipAddress != 'None') {
                        assetList1 += asset.ipAddress
                    }
                }
                //cvmtConfig.yml asset list values
                String assetList2 = grailsApplication.config.getProperty('acasArrayList', String.class)
                //Converts text string from cvmtConfig.yml to String list
                ArrayList<String> assets = []
                String[] assets1 = assetList2.split(',')
                for (asset1 in assets1) {
                    assets.add(asset1)
                }

                //CVMT IpsList (Alternate IPs)
                ArrayList ipsList = []
                List<Ips> ipsList1 = Ips.list()
                if (ipsList1) {
                    for (entry in ipsList1) {
                        ipsList.add(entry.ipAddress)
                    }
                }
                //add CVMT alternate IPs list to CVMT current assets' IPs
                List<String> ipAll = ipsList + assetList1
                //skip assets with Horizon View prefixes (also includes quarantine subnet (192.168.99))
                String horizonViewPrefixValues = grailsApplication.config.getProperty('horizonPrefix', String.class)
                if (horizonViewPrefixValues) {
                    List<String> horizonViewPrefixes = horizonViewPrefixValues.split(',')
                    String json = ""
                    //for each cvmtConfig.yml asset list value
                    for (asset in assets) {
                        //retrieve a list of assets (name/ipAddress) for that asset id
                        String query = "?fields=repositories,viewableIPs"
                        String uri = grailsApplication.config.getProperty('acasUrl', String.class) + '/rest/asset/' + asset + query
                        def sslContext1 = SSLContexts.createSystemDefault()

                        def tlsStrategy = ClientTlsStrategyBuilder.create()
                                .setSslContext(sslContext1)
                                .buildClassic()

                        PoolingHttpClientConnectionManager connectionManager =
                                PoolingHttpClientConnectionManagerBuilder.create()
                                        .setTlsSocketStrategy(tlsStrategy)
                                        .build()

                        CloseableHttpClient httpClient = HttpClients.custom()
                                .setConnectionManager(connectionManager)
                                .build()
                        try {
                            HttpGet httpGet = new HttpGet(uri)
                            httpGet.addHeader("Cookie", cookie)
                            httpGet.addHeader("Content-Type", "application/json")
                            httpGet.addHeader("X-SecurityCenter", token)
                            HttpClientContext clientContext = HttpClientContext.create()
                            httpClient.execute(httpGet, clientContext, response -> {
                                json = EntityUtils.toString(response.getEntity())
                            })
                        } catch (e) {
                            log.error(e.getMessage())
                            log.error "Failed retrieving asset list"
                        } finally {
                            httpClient.close()
                        }

                        def jsonSlurper = new JsonSlurper()
                        def json1 = jsonSlurper.parseText(json)
                        for (def result in json1.response.viewableIPs) {
                            def result1 = result.ipList
                            result1.eachLine { String it ->
                                //extract IP Address from each line
                                def matcher = (it =~ /\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/)
                                matcher ? matcher[0] : null
                                if (matcher != null) {
                                    try {
                                        def ipAddress = matcher[0][0]
                                        //If returned IP Address is not null and IP address is not found in list (helpful for repeat values from ACAS retrieval)
                                        if (!ipAll.contains(ipAddress)) {
                                            //Attempt to get host name value from string
                                            String host = it.replaceAll("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}[|]", "")
                                            if (host == "") {
                                                host = "none"
                                            }
                                            //Get host name using query to Infoblox
                                            Map<String, Object> result2 = lookupService.getName1(host, ipAddress)
                                            //if lookup verifies asset can be added (createAsset=true)
                                            //If DNS entry exists, use the host name/a record
                                            if (result2.createAsset) {
                                                Aor aor = Aor.findWhere(name: "NoAOR")
                                                Poc poc = Poc.findWhere(name: "NoPOC")
                                                host = result2.assetName

                                                //Determine if hostname has a Horizon View Prefix - do not retrieve
                                                Boolean horizonViewPrefix = false
                                                for (horizonViewPrefix1 in horizonViewPrefixes) {
                                                    if (ipAddress.startsWith(horizonViewPrefix1)) {
                                                        horizonViewPrefix = true
                                                    }
                                                }
                                                //if host name does not have a Horizon asset prefix
                                                if (!horizonViewPrefix) {
                                                    //Check to see if asset relationship exists
                                                    List<AssetRelationship> assetRelationships = AssetRelationship.list()
                                                    //If an asset relationship exists
                                                    if (assetRelationships) {
                                                        //use asset relationship to set AOR and POC
                                                        for (entry in assetRelationships) {
                                                            if (host.startsWith(entry.name)) {
                                                                aor = entry.aor
                                                                poc = entry.poc
                                                            }
                                                        }
                                                    }
                                                    //if the ipAll list doesn't contain the IP Address, add the entry to the list
                                                    if (!ipAll.contains(ipAddress)) {
                                                        //add ip address to ipAll list
                                                        ipAll += ipAddress
                                                        String opSystem = getAssetOS(map, ipAddress)
                                                        Subnet subnetValue = Subnet.findWhere(description: "NA")
                                                        try {
                                                            Asset assetValue1 = new Asset(name: host, description: "NA", subnet: subnetValue,
                                                                    poc: poc, aor: aor, ipAddress: ipAddress, opSystem: opSystem)
                                                            assetValue1.save(flush: true)
                                                            log.warn("Added new asset: ${host}")
                                                        } catch (e) {
                                                            log.error(e.getMessage())
                                                            log.error("Error saving new asset: ${host}")
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    catch (e) {
                                        log.error ("Incorrect format for IP Address: " + it)
                                        log.error(e.getMessage())
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            log.error("No token provided for asset import")
        }
    }

    //Delete assets from .CSV list
    def deleteBulkAsset(def fileData) {
        String file = new String(fileData, "UTF-8")
        def lines = file.readLines()
        for (line in lines) {
            def asset = Asset.findWhere(ipAddress: line.toString())
            if (asset) {
                log.warn("Deleting: ${asset}")
                asset.delete(flush: true)
            }
        }
    }

    //Get numerical patch vulnerability score for each asset
    //job and button on Maintenance view
    @Transactional
    def getScore() {
        List<Asset> assetList = Asset.list()
        for (asset in assetList) {
            int scoreTotal = 0
            List vulnerabilityDetailList = VulnerabilityDetail.findAllWhere(asset: asset)
            if (vulnerabilityDetailList) {
                int score = 0
                for (vulnerabilityDetail in vulnerabilityDetailList) {
                    if (vulnerabilityDetail.vulnerability.severity == "Critical") {
                        score = 40
                    } else if (vulnerabilityDetail.vulnerability.severity == "High") {
                        score = 10
                    } else if (vulnerabilityDetail.vulnerability.severity == "Medium") {
                        score = 3
                    } else if (vulnerabilityDetail.vulnerability.severity == "Low") {
                        score = 1
                    }
                    scoreTotal += score
                }
                asset.score = scoreTotal.toString()
            } else {
                asset.score = "0"
            }
            asset.save()
        }
    }

    //Get numerical patch vulnerability score for one asset
    //invoked when updating patch state of a vulnerability
    def getScore1(Asset asset) {
        int scoreTotal = 0
        List vulnerabilityDetailList = VulnerabilityDetail.findAllWhere(asset: asset)
        if (vulnerabilityDetailList) {
            int score = 0
            for (vulnerabilityDetail in vulnerabilityDetailList) {
                if (vulnerabilityDetail.vulnerability.severity == "Critical") {
                    score = 30
                } else if (vulnerabilityDetail.vulnerability.severity == "High") {
                    score = 10
                } else if (vulnerabilityDetail.vulnerability.severity == "Medium") {
                    score = 3
                } else if (vulnerabilityDetail.vulnerability.severity == "Low") {
                    score = 1
                }
                scoreTotal += score
            }
        } else {
            scoreTotal = 0
        }
        asset.score = scoreTotal.toString()
        asset.save()
    }

    //Get asset's operating system during initial asset addition
    def getAssetOS(Map map, String ipAddress) {
        String token = "${map.get("token")}"
        String cookie = "${map.get("cookie")}"
        if (cookie != "null") {
            SSLContext sslContext = lookupService.getSslContext()
            String json = ""
            def query = '{' +
                    '"query": {' +
                    '"type": "vuln",' +
                    '"tool": "listos",' +
                    '"sourceType": "cumulative",' +
                    '"filters": [' +
                    '{' +
                    '"id":"ip",' +
                    '"filterName": "ip",' +
                    '"operator": "=",' +
                    '"value": "' + ipAddress + '"' +
                    '}' +
                    ']' +
                    '},' +
                    '"sourceType": "cumulative",' +
                    '"type": "vuln"' +
                    '}'
            String uri = grailsApplication.config.getProperty('acasUrl', String.class) + '/rest/analysis'
            def sslContext1 = SSLContexts.createSystemDefault()

            def tlsStrategy = ClientTlsStrategyBuilder.create()
                    .setSslContext(sslContext1)
                    .buildClassic()

            PoolingHttpClientConnectionManager connectionManager =
                    PoolingHttpClientConnectionManagerBuilder.create()
                            .setTlsSocketStrategy(tlsStrategy)
                            .build()

            CloseableHttpClient httpClient = HttpClients.custom()
                    .setConnectionManager(connectionManager)
                    .build()
            try {
                HttpPost httpPost = new HttpPost(uri)
                httpPost.addHeader("Cookie", cookie)
                httpPost.addHeader("Content-Type", "application/json")
                httpPost.addHeader("X-SecurityCenter", token)
                StringEntity entity = new StringEntity(query)
                httpPost.setEntity(entity)

                HttpClientContext clientContext = HttpClientContext.create()
                httpClient.execute(httpPost, clientContext, response -> {
                    json = EntityUtils.toString(response.getEntity())
                })
            } catch (e) {
                log.error(e.getMessage())
                log.error("IP Address: ${ipAddress} has OS retrieval error:" + e)
            } finally {
                httpClient.close()
            }
            def jsonSlurper = new JsonSlurper()
            def json1 = jsonSlurper.parseText(json)
            String osResult = json1.response.results.name
            String osResult1 = osResult.replaceAll("\\[", '')
            String osResult2 = osResult1.replaceAll(']', '')
            String result
            if (osResult2) {
                result = osResult2
            } else {
                result = "No OS found in ACAS"
            }
            return result
        } else {
            log.error("No token for asset getOS job.")
        }
    }

    //update subnet for each asset
    @Transactional
    def setSubnets() {
        List<Subnet> subnetList = Subnet.list()
        List<Asset> assets = Asset.list()
        Subnet subnet1 = Subnet.findWhere(description: "NA")
        for (asset in assets) {
            if (asset.ipAddress != "None") {
                def foundSubnet = false
                subnetList.each { Subnet subnet ->
                    if (asset.ipAddress.contains(subnet.subnet)) {
                        foundSubnet = true
                        asset.subnet = subnet
                    }
                }
                if (!foundSubnet) {
                    asset.subnet = subnet1
                }
                asset.save()
            }
        }
    }

    @Transactional
    def assetRemove(Asset asset) {
        if (asset.stigAsset) {
            deleteAsset(asset.id)
            asset.delete(flush: true)
        } else {
            log.warn "Delete asset: " + asset.name
            asset.delete(flush: true)
        }
    }

    //runs service to update all assets' operating systems
    @Transactional
    def getOpSystems(Map map) {
        String token = "${map.get("token")}"
        String cookie = "${map.get("cookie")}"
        if (cookie != "null") {
            List<Asset> assets = Asset.list()
            for (asset in assets) {
                if (asset.ipAddress != 'None') {
                    SSLContext sslContext = lookupService.getSslContext()
                    String json = ""
                    def query = '{' +
                            '"query": {' +
                            '"type":"vuln", ' +
                            '"tool":"listos", ' +
                            '"filters": [' +
                            '{"id": "ip", ' +
                            '"filterName": "ip", ' +
                            '"operator": "=",' +
                            '"value": "' + asset.ipAddress + '"}' +
                            ']' +
                            '},' +
                            '"type":"vuln", ' +
                            '"tool":"listos", ' +
                            '"sourceType":"cumulative", ' +
                            '"startOffset":0, ' +
                            '"endOffset":5}'
                    String uri = grailsApplication.config.getProperty('acasUrl', String.class) + '/rest/analysis'
                    def sslContext1 = SSLContexts.createSystemDefault()

                    def tlsStrategy = ClientTlsStrategyBuilder.create()
                            .setSslContext(sslContext1)
                            .buildClassic()

                    PoolingHttpClientConnectionManager connectionManager =
                            PoolingHttpClientConnectionManagerBuilder.create()
                                    .setTlsSocketStrategy(tlsStrategy)
                                    .build()

                    CloseableHttpClient httpClient = HttpClients.custom()
                            .setConnectionManager(connectionManager)
                            .build()
                    try {
                        HttpPost httpPost = new HttpPost(uri)
                        httpPost.addHeader("Cookie", cookie)
                        httpPost.addHeader("Content-Type", "application/json")
                        httpPost.addHeader("X-SecurityCenter", token)
                        StringEntity entity = new StringEntity(query)
                        httpPost.setEntity(entity)
                        HttpClientContext clientContext = HttpClientContext.create()
                        httpClient.execute(httpPost, clientContext, response -> {
                            json = EntityUtils.toString(response.getEntity())
                        })
                    } catch (e) {
                        log.error("Service has OS retrieval error:" + e.getMessage())
                    } finally {
                        httpClient.close()
                    }
                    def jsonSlurper = new JsonSlurper()
                    def json1 = jsonSlurper.parseText(json)
                    try {
                        String opSystem = json1.response.results[0].name
                        if (opSystem) {
                            def opSystemList = opSystem.split("\n")
                            asset.opSystem = opSystemList[0]
                        } else {
                            asset.opSystem = "No OS found in ACAS"
                        }
                        asset.save()
                    } catch (e) {
                        e.getMessage()
                        asset.opSystem = "No OS found in ACAS"
                        asset.save()
                    }
                }
            }
        }
    }

    @Transactional
    def deleteAsset(Long id) {
        Asset asset = Asset.findWhere(id: id)
        if (asset) {
            List<StigAsset> stigAssets = StigAsset.findAllWhere(asset: asset)
            if (stigAssets) {
                for (stigAsset in stigAssets) {
                    List<AssetStigVulnStatus> assetStigVulnStatusList = AssetStigVulnStatus.findAllWhere(stigAsset: stigAsset)
                    if (assetStigVulnStatusList) {
                        for (assetStigVulnStatus in assetStigVulnStatusList) {
                            assetStigVulnStatus.delete(flush: true)
                        }
                    }
                }
            }
        }
    }

    //check ACAS for CVMT asset entries
    @Transactional
    def checkAcas(Map map) {
        String token = "${map.get("token")}"
        String cookie = "${map.get("cookie")}"
        if (cookie != "null") {
            SSLContext sslContext = lookupService.getSslContext()
            //create a list of asset IP addresses
            def assetList = Asset.findAll()
            def assetList1 = []
            def acasIpList = []
            if (assetList) {
                for (asset in assetList) {
                    if (asset.ipAddress != 'None') {
                        assetList1 += asset.ipAddress
                    }
                }
                //cvmtConfig.yml asset list values
                String assetList2 = grailsApplication.config.getProperty('acasArrayList', String.class)
                //Converts text string from cvmtConfig.yml to String list
                ArrayList<String> assets = []
                String[] assets1 = assetList2.split(',')
                for (asset1 in assets1) {
                    assets.add(asset1)
                }
                String json = ""
                //for each cvmtConfig.yml asset list value
                for (asset in assets) {
                    //retrieve a list of assets (name/ipAddress) for that asset id
                    String query = "?fields=repositories,viewableIPs"
                    String uri = grailsApplication.config.getProperty('acasUrl', String.class) + '/rest/asset/' + asset + query
                    def sslContext1 = SSLContexts.createSystemDefault()

                    def tlsStrategy = ClientTlsStrategyBuilder.create()
                            .setSslContext(sslContext1)
                            .buildClassic()

                    PoolingHttpClientConnectionManager connectionManager =
                            PoolingHttpClientConnectionManagerBuilder.create()
                                    .setTlsSocketStrategy(tlsStrategy)
                                    .build()

                    CloseableHttpClient httpClient = HttpClients.custom()
                            .setConnectionManager(connectionManager)
                            .build()
                    try {
                        HttpGet httpGet = new HttpGet(uri)
                        httpGet.addHeader("Cookie", cookie)
                        httpGet.addHeader("Content-Type", "application/json")
                        httpGet.addHeader("X-SecurityCenter", token)
                        HttpClientContext clientContext = HttpClientContext.create()
                        httpClient.execute(httpGet, clientContext, response -> {
                            json = EntityUtils.toString(response.getEntity())
                        })
                    } catch (e) {
                        log.error(e.getMessage())
                        log.error "Failed retrieving asset list"
                    } finally {
                        httpClient.close()
                    }

                    def jsonSlurper = new JsonSlurper()
                    def json1 = jsonSlurper.parseText(json)
                    for (def result in json1.response.viewableIPs) {
                        def result1 = result.ipList
                        result1.eachLine { String it ->
                            //extract IP Address from each response line
                            def matcher = (it =~ /\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/)
                            matcher ? matcher[0] : null
                            try {
                                if (matcher != null) {
                                    def ipAddress = matcher[0][0]
                                    acasIpList += ipAddress
                                }
                            }
                            catch (e) {
                                log.error ("Error string: " + it)
                                log.error (e.getMessage())
                            }
                        }
                    }
                }
                //for each IP Address in CVMT asset list
                for (assetIpAddress in assetList1) {
                    //check to see if the ACAS asset list contains each CVMT asset IP Address
                    //if it doesn't, log it
                    if (!acasIpList.contains(assetIpAddress)) {
                        Asset asset2 = Asset.findWhere(ipAddress: assetIpAddress)
                        log.warn ("No ACAS entry for ${asset2.name} with IP Address: ${asset2.ipAddress} and AOR: ${asset2.aor.name} and POC: ${asset2.poc.name}")
                        log.warn ("Deleting asset ${asset2.name}")
                        deleteAsset(asset2.id)
                        asset2.delete()
                    }
                }
            }
        }
        else {
            log.error ("No ACAS Cookie received.")
        }
    }
}
