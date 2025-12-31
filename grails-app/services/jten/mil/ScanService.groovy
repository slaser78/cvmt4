package jten.mil

import grails.core.GrailsApplication
import grails.gorm.transactions.ReadOnly
import grails.gorm.transactions.Transactional
import groovy.json.JsonSlurper
import org.apache.hc.client5.http.classic.methods.HttpGet
import org.apache.hc.client5.http.classic.methods.HttpPatch
import org.apache.hc.client5.http.classic.methods.HttpPost
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder
import org.apache.hc.core5.http.io.entity.EntityUtils
import org.apache.hc.core5.http.io.entity.StringEntity
import org.apache.hc.core5.ssl.SSLContexts
import javax.net.ssl.SSLContext

@Transactional
class ScanService {
    GrailsApplication grailsApplication
    def lookupService
    //Perform patch scan of one asset
    @ReadOnly
    def setScan(Map map, Asset asset) {
        String token = "${map.get("token")}"
        String cookie = "${map.get("cookie")}"
        if (cookie) {
            int scanId = grailsApplication.config.getProperty("acasScanId", String) as int
            def sslContext = SSLContexts.createSystemDefault()
            def tlsStrategy = ClientTlsStrategyBuilder.create()
                    .setSslContext(sslContext1)
                    .buildClassic()

            PoolingHttpClientConnectionManager connectionManager =
                    PoolingHttpClientConnectionManagerBuilder.create()
                            .setTlsSocketStrategy(tlsStrategy)
                            .build()
            def httpClient = lookupService.httpClient()
            String query = '{"ipList":"' + asset.ipAddress + '"}'
            String uri = grailsApplication.config.getProperty('acasUrl', String.class) + "/rest/scan/${scanId}"
            String json = null
            try {
                HttpPatch httpPatch = new HttpPatch(uri)
                httpPatch.addHeader("Cookie", cookie)
                httpPatch.addHeader("Content-Type", "application/json")
                httpPatch.addHeader("X-SecurityCenter", token)
                StringEntity entity = new StringEntity(query)
                httpPatch.setEntity(entity)
                httpClient.execute(httpPatch, clientContext, response -> {
                    json = EntityUtils.toString(response.getEntity())
                })
            } catch (e) {
                log.error(e.getMessage())
                log.error("Asset: ${asset.name} has patch retrieval error:")
            } finally {
                httpClient.close()
            }
            //Run Scan
            int scanJobId = runScan(token, cookie, scanId)
            return (scanJobId)
        }
    }

    @ReadOnly
    def runScan(String token, String cookie, Integer scanId) {
        def uri = grailsApplication.config.getProperty('acasUrl', String.class) + "/rest/scan/${scanId}/launch"
        String json = ""
        SSLContext sslContext = lookupService.getSslContext()
        def tlsStrategy = ClientTlsStrategyBuilder.create()
                .setSslContext(sslContext1)
                .buildClassic()

        PoolingHttpClientConnectionManager connectionManager =
                PoolingHttpClientConnectionManagerBuilder.create()
                        .setTlsSocketStrategy(tlsStrategy)
                        .build()
        def httpClient = lookupService.httpClient()
        try {
            HttpPost httpPost = new HttpPost(uri)
            httpPost.addHeader("Cookie", cookie)
            httpPost.addHeader("Content-Type", "application/json")
            httpPost.addHeader("X-SecurityCenter", token)
            httpClient.execute(httpPost, clientContext, response -> {
                json = EntityUtils.toString(response.getEntity())
            })
        } catch (e) {
            log.error(e.getMessage())
            log.error("Scan initiation has an error.")
        } finally {
            httpClient.close()
        }
        JsonSlurper jsonSlurper = new JsonSlurper()
        def http1 = jsonSlurper.parseText(json)
        int scanResult = http1.response.scanResult.id as int
        log.warn ("Scan Result: " + scanResult)
        return scanResult
    }

    //get patch last scan time for one asset
    @ReadOnly
    def getScanTime(Map map, int scanRunId) {
        String token = "${map.get("token")}"
        String cookie = "${map.get("cookie")}"
        if (cookie) {
            def sslContext = SSLContexts.createSystemDefault()
            def tlsStrategy = ClientTlsStrategyBuilder.create()
                    .setSslContext(sslContext)
                    .buildClassic()

            PoolingHttpClientConnectionManager connectionManager =
                    PoolingHttpClientConnectionManagerBuilder.create()
                            .setTlsSocketStrategy(tlsStrategy)
                            .build()
            def httpClient = lookupService.httpClient()
            def uri = grailsApplication.config.getProperty('acasUrl', String.class) + "/rest/scanResult/${scanRunId}"
            String json = ""
            try {
                HttpGet httpGet = new HttpGet(uri)
                httpGet.addHeader("Cookie", cookie)
                httpGet.addHeader("Content-Type", "application/json")
                httpGet.addHeader("X-SecurityCenter", token)
                httpClient.execute(httpGet, clientContext, response -> {
                    json = EntityUtils.toString(response.getEntity())
                })
            } catch (e) {
                log.error(e.getMessage())
                log.error("Scan initiation has an error.")
            } finally {
                httpClient.close()
            }
            JsonSlurper jsonSlurper = new JsonSlurper()
            def http1 = jsonSlurper.parseText(json)
            def finishTime = http1.response.finishTime
            if (finishTime == "-1") {
                return ("Not finished")
            } else {
                return ("Finished")
            }
        }
    }

    //get ACAS last patch scan details info for all assets
    def getScanDetails(Map map) {
        String token = "${map.get("token")}"
        String cookie = "${map.get("cookie")}"
        if (cookie != "null") {
            def sslContext = SSLContexts.createSystemDefault()
            String repository = grailsApplication.config.getProperty('acasRepositories', String.class)
            List<Asset> assetList = Asset.list()
            for (asset in assetList) {
                if (asset.ipAddress != "None") {
                    List<VulnerabilityDetail> vulnerabilityDetails = VulnerabilityDetail.findAllWhere(asset: asset)
                    if (vulnerabilityDetails) {
                        String json = ""
                        def query = '{ ' +
                                '"query": {' +
                                '"type":"vuln",' +
                                '"tool":"vulndetails",' +
                                '"filters":[' +
                                '{"id":"repository",' +
                                '"filterName":"repositoryIDs",' +
                                '"operator":"=",' +
                                '"value":"' + repository + '"},' +
                                '{"id":"ip",' +
                                '"filterName":"ip",' +
                                '"operator":"=",' +
                                '"value":"' + asset.ipAddress + '"},' +
                                '{"id":"severity",' +
                                '"filterName": "severity",' +
                                '"operator":"=",' +
                                '"value":"1,2,3,4"}' +
                                ']' +
                                '},' +
                                '"type": "vuln", ' +
                                '"tool": "vulndetails", ' +
                                '"sourceType": "cumulative", ' +
                                '"startOffset":0, ' +
                                '"endOffset":5000' +
                                '}'
                        String uri = grailsApplication.config.getProperty('acasUrl', String.class) + '/rest/analysis'
                        def tlsStrategy = ClientTlsStrategyBuilder.create()
                                .setSslContext(sslContext1)
                                .buildClassic()

                        PoolingHttpClientConnectionManager connectionManager =
                                PoolingHttpClientConnectionManagerBuilder.create()
                                        .setTlsSocketStrategy(tlsStrategy)
                                        .build()
                        def httpClient = lookupService.httpClient()
                        try {
                            HttpPost httpPost = new HttpPost(uri)
                            httpPost.addHeader("Cookie", cookie)
                            httpPost.addHeader("Content-Type", "application/json")
                            httpPost.addHeader("X-SecurityCenter", token)
                            StringEntity entity = new StringEntity(query)
                            httpPost.setEntity(entity)
                            httpClient.execute(httpPost, clientContext, response -> {
                                json = EntityUtils.toString(response.getEntity())
                            })
                        } catch (e) {
                            log.error(e.getMessage())
                            log.error("ACAS Vulnerability Details retrieval error:" + e)
                        } finally {
                            httpClient.close()
                        }
                        def jsonSlurper = new JsonSlurper()
                        try {
                            def json1 = jsonSlurper.parseText(json)
                            ArrayList acasVulnList = []
                            for (result in json1.response.results) {
                                if (result.ip == asset.ipAddress) {
                                    acasVulnList += result
                                }
                                for (acasVuln in acasVulnList) {
                                    String pluginId = (result.pluginID).toString()
                                    for (vulnerabilityDetail in vulnerabilityDetails) {
                                        if (vulnerabilityDetail.vulnerability.plugin == pluginId) {
                                            String firstSeenValue = result.firstSeen
                                            Long firstSeen = Long.valueOf(firstSeenValue)
                                            Date firstSeen1 = new Date(firstSeen * 1000)
                                            vulnerabilityDetail.firstSeen = firstSeen1
                                            //Apply to critical assets only
                                            if (vulnerabilityDetail.asset.crit == true) {
                                                vulnerabilityDetail.suspenseDate = firstSeen1 + 20
                                            } else {
                                                vulnerabilityDetail.suspenseDate = firstSeen1 + 30
                                            }
                                            if (result.solution) {
                                                def solution = result.solution
                                                if (solution.size() > 10000) {
                                                    log.warn ("Solution size is: " + solution.size())
                                                }
                                                vulnerabilityDetail.solution = result.solution
                                            } else {
                                                vulnerabilityDetail.solution = "None provided by ACAS"
                                            }
                                            if (result.description) {
                                                String description = result.description
                                                if (description.size() > 50000) {
                                                    log.warn ("Description size is: " + description.size())
                                                }
                                                vulnerabilityDetail.description = result.description
                                            } else {
                                                vulnerabilityDetail.description = "None provided by ACAS"
                                            }
                                            if (result.pluginText) {
                                                String pluginText = result.pluginText.toString()
                                                String pluginText1 = pluginText.takeBetween("<plugin_output>", "</plugin_output>")
                                                if (pluginText1.size() > 40000) {
                                                    log.warn ("Plugin Text size is: " + pluginText1.size())
                                                }
                                                vulnerabilityDetail.pluginText = pluginText1
                                                vulnerabilityDetails -= vulnerabilityDetail
                                            } else {
                                                vulnerabilityDetail.pluginText = "None provided by ACAS"
                                            }
                                            vulnerabilityDetail.save(flush:true)
                                        }
                                    }
                                }
                            }
                        } catch (e) {
                            log.error(e.getMessage())
                        }
                    }
                }
            }
        } else {
            log.error ("No Cookie")
        }
    }

    def getScanDetails1(Map map, Asset asset) {
        String token = "${map.get("token")}"
        String cookie = "${map.get("cookie")}"
        if (cookie != "null") {
            String ipAddress = asset.ipAddress
            def sslContext = SSLContexts.createSystemDefault()
            String repository = grailsApplication.config.getProperty('acasRepositories', String.class)
            String json = ""
            def query = '{ ' +
                    '"query": {' +
                    '"type":"vuln",' +
                    '"tool":"vulndetails",' +
                    '"filters":[' +
                    '{"id":"repository",' +
                    '"filterName":"repositoryIDs",' +
                    '"operator":"=",' +
                    '"value":"' + repository + '"},' +
                    '{"id":"ip",' +
                    '"filterName":"ip",' +
                    '"operator":"=",' +
                    '"value":"' + ipAddress + '"},' +
                    '{"id":"severity",' +
                    '"filterName": "severity",' +
                    '"operator":"=",' +
                    '"value":"1,2,3,4"}' +
                    ']' +
                    '},' +
                    '"type": "vuln", ' +
                    '"tool": "vulndetails", ' +
                    '"sourceType": "cumulative", ' +
                    '"startOffset":0, ' +
                    '"endOffset":5000' +
                    '}'
            String uri = grailsApplication.config.getProperty('acasUrl', String.class) + '/rest/analysis'
            def tlsStrategy = ClientTlsStrategyBuilder.create()
                    .setSslContext(sslContext1)
                    .buildClassic()

            PoolingHttpClientConnectionManager connectionManager =
                    PoolingHttpClientConnectionManagerBuilder.create()
                            .setTlsSocketStrategy(tlsStrategy)
                            .build()
            def httpClient = lookupService.httpClient()
            try {
                HttpPost httpPost = new HttpPost(uri)
                httpPost.addHeader("Cookie", cookie)
                httpPost.addHeader("Content-Type", "application/json")
                httpPost.addHeader("X-SecurityCenter", token)
                StringEntity entity = new StringEntity(query)
                httpPost.setEntity(entity)
                httpClient.execute(httpPost, clientContext, response -> {
                    json = EntityUtils.toString(response.getEntity())
                })
            } catch (e) {
                log.error(e.getMessage())
                log.error("ACAS Vulnerability Details retrieval error:" + e)
            } finally {
                httpClient.close()
            }
            def jsonSlurper = new JsonSlurper()
            try {
                def json1 = jsonSlurper.parseText(json)
                List<VulnerabilityDetail> vulnerabilityDetails = VulnerabilityDetail.findAllWhere(asset: asset)
                ArrayList acasVulnList = []
                for (result in json1.response.results) {
                    if (result.ip == asset.ipAddress) {
                        acasVulnList += result
                    }
                    for (acasVuln in acasVulnList) {
                        String pluginId = (result.pluginID).toString()
                        for (vulnerabilityDetail in vulnerabilityDetails) {
                            if (vulnerabilityDetail.vulnerability.plugin == pluginId) {
                                String firstSeenValue = result.firstSeen
                                Long firstSeen = Long.valueOf(firstSeenValue)
                                Date firstSeen1 = new Date(firstSeen * 1000)
                                vulnerabilityDetail.firstSeen = firstSeen1
                                vulnerabilityDetail.solution = result.solution
                                vulnerabilityDetail.description = result.description
                                if (result.pluginText) {
                                    String pluginText = result.pluginText.toString()
                                    String pluginText1 = pluginText.takeBetween("<plugin_output>", "</plugin_output>")
                                    vulnerabilityDetail.pluginText = pluginText1
                                    vulnerabilityDetails -= vulnerabilityDetail
                                } else {
                                    vulnerabilityDetail.pluginText = "None"
                                }
                                vulnerabilityDetail.save()
                            }
                        }
                    }
                }
            } catch (e) {
                log.error(e.getMessage())
            }
        }
    }

    //get ACAS last asset patch scan detail info for one asset (Credentialed/Uncredentialed)
    def getAssetScanDetails (def map, Asset asset) {
        String token = "${map.get("token")}"
        String cookie = "${map.get("cookie")}"
        if (cookie != "null") {
            String ipAddress = asset.ipAddress
            def sslContext = SSLContexts.createSystemDefault()
            String repository = grailsApplication.config.getProperty('acasRepositories', String.class)
            String json = ""
            def query = '{ ' +
                    '"query": {' +
                    '"type": "vuln",' +
                    '"tool": "vulndetails",' +
                    '"filters":[{' +
                    '"id":"ip",' +
                    '"filterName":"ip",' +
                    '"operator":"=",' +
                    '"value":"' + ipAddress + '"' +
                    '}, ' +
                    '{"id":"pluginID",' +
                    '"filterName": "pluginID",' +
                    '"operator":"=",' +
                    '"value":"19506"' +
                    '}, ' +
                    '{' +
                    '"id":"repository",' +
                    '"filterName":"repositoryIDs",' +
                    '"operator":"=",' +
                    '"value":"'+ repository +'"}' +
                    ']' +
                    '},' +
                    '"type": "vuln", ' +
                    '"tool": "vulndetails", ' +
                    '"sourceType": "cumulative", ' +
                    '"startOffset":0, ' +
                    '"endOffset":20' +
                    '}'
            String uri = grailsApplication.config.getProperty('acasUrl', String.class) + '/rest/analysis'
            def tlsStrategy = ClientTlsStrategyBuilder.create()
                    .setSslContext(sslContext1)
                    .buildClassic()

            PoolingHttpClientConnectionManager connectionManager =
                    PoolingHttpClientConnectionManagerBuilder.create()
                            .setTlsSocketStrategy(tlsStrategy)
                            .build()
            def httpClient = lookupService.httpClient()
            try {
                HttpPost httpPost = new HttpPost(uri)
                httpPost.addHeader("Cookie", cookie)
                httpPost.addHeader("Content-Type", "application/json")
                httpPost.addHeader("X-SecurityCenter", token)
                StringEntity entity = new StringEntity(query)
                httpPost.setEntity(entity)
                httpClient.execute(httpPost, clientContext, response -> {
                    json = EntityUtils.toString(response.getEntity())
                })
            } catch (e) {
                log.error(e.getMessage())
                log.error("ACAS Vulnerability Details retrieval error:" + e)
            } finally {
                httpClient.close()
            }
            def jsonSlurper = new JsonSlurper()
            //Change text string to json formatted string
            def jsonParsed = jsonSlurper.parseText(json)
            def resultCount = jsonParsed.response.results.size()
            //Ensure results exist
            if (resultCount > 0) {
                def jsonParsedFirstResult = jsonParsed.response.results[0]
                if (jsonParsedFirstResult) {
                    if (jsonParsedFirstResult.pluginText.contains("Credentialed_Scan:true")) {
                        def matcher = (jsonParsedFirstResult.pluginText =~ /LastAuthenticatedResults:\d+/)
                        String authenticatedResults = ""
                        if (matcher.find()) {
                            authenticatedResults = matcher.group(0)
                        }
                        String authenticatedResults1 = authenticatedResults.replace("LastAuthenticatedResults:", "")
                        Long authenticatedResults2 = Long.valueOf(authenticatedResults1)
                        def lastScan = new Date(authenticatedResults2 * 1000)
                        asset.lastScan = lastScan
                        asset.credentialedScan = true
                        asset.save()
                    } else if (jsonParsedFirstResult.pluginText.contains('LastUnauthenticatedResults:')) {
                        def matcher = (jsonParsedFirstResult.pluginText =~ /LastUnauthenticatedResults:\d+/)
                        String unauthenticatedResults = ""
                        if (matcher.find()) {
                            unauthenticatedResults = matcher.group(0)
                        }
                        String unauthenticatedResults1 = unauthenticatedResults.replace("LastUnauthenticatedResults:", "")
                        Long unauthenticatedResults2 = Long.valueOf(unauthenticatedResults1)
                        Date lastScan = new Date(unauthenticatedResults2 * 1000)
                        asset.lastScan = lastScan
                        asset.credentialedScan = false
                        asset.save()
                    } else if (jsonParsedFirstResult.pluginText.contains("Credentialed checks : yes")) {
                        String lastSeen1 = jsonParsedFirstResult.lastSeen
                        Long lastSeenLong = Long.valueOf(lastSeen1)
                        asset.lastScan = new Date(lastSeenLong * 1000)
                        asset.credentialedScan = true
                        asset.save()
                    } else if (jsonParsedFirstResult.pluginText.contains("Credentialed checks : no")) {
                        String lastSeen1 = jsonParsedFirstResult.lastSeen
                        Long lastSeenLong = Long.valueOf(lastSeen1)
                        asset.lastScan = new Date(lastSeenLong * 1000)
                        asset.credentialedScan = false
                        asset.save()
                    } else {
                        log.error("No scan data in either repository for asset: ${asset.name}")
                    }
                }
            }
        }
    }

    //get ACAS last patch scan details info for all assets
    @Transactional
    def getAssetScanDetails1 (def map) {
        String token = "${map.get("token")}"
        String cookie = "${map.get("cookie")}"
        if (cookie != "null") {
            def sslContext = SSLContexts.createSystemDefault()
            String repository = grailsApplication.config.getProperty('acasRepositories', String.class)
            String json = ""
            def query = '{ ' +
                    '"query": {' +
                    '"type": "vuln",' +
                    '"tool": "vulndetails",' +
                    '"filters":[' +
                    '{"id":"repository",' +
                    '"filterName":"repositoryIDs",' +
                    '"operator":"=",' +
                    '"value":"' + repository + '"},' +
                    '{"id":"pluginID",' +
                    '"filterName": "pluginID",' +
                    '"operator":"=",' +
                    '"value":"19506"' +
                    '}' +
                    ']' +
                    '},' +
                    '"type": "vuln", ' +
                    '"tool": "vulndetails", ' +
                    '"sourceType": "cumulative", ' +
                    '"startOffset":0, ' +
                    '"endOffset":2000' +
                    '}'
            String uri = grailsApplication.config.getProperty('acasUrl', String.class) + '/rest/analysis'
            def tlsStrategy = ClientTlsStrategyBuilder.create()
                    .setSslContext(sslContext1)
                    .buildClassic()

            PoolingHttpClientConnectionManager connectionManager =
                    PoolingHttpClientConnectionManagerBuilder.create()
                            .setTlsSocketStrategy(tlsStrategy)
                            .build()

            def httpClient = lookupService.httpClient()
            try {
                HttpPost httpPost = new HttpPost(uri)
                httpPost.addHeader("Cookie", cookie)
                httpPost.addHeader("Content-Type", "application/json")
                httpPost.addHeader("X-SecurityCenter", token)
                StringEntity entity = new StringEntity(query)
                httpPost.setEntity(entity)
                httpClient.execute(httpPost, clientContext, response -> {
                    json = EntityUtils.toString(response.getEntity())
                })
            } catch (e) {
                log.error(e.getMessage())
                log.error("ACAS Vulnerability Details retrieval error:" + e)
            } finally {
                httpClient.close()
            }
            def jsonSlurper = new JsonSlurper()
            def json1 = jsonSlurper.parseText(json)
            if (json1.response.results) {
                for (json2 in json1.response.results) {
                    String ipAddress = (json2.ip).toString()
                    Asset asset = Asset.findWhere(ipAddress: ipAddress)
                    if (asset) {
                        if (json2.pluginText.contains("Credentialed_Scan:true")) {
                            def matcher = (json2.pluginText =~ /LastAuthenticatedResults:\d+/)
                            String authenticatedResults = ""
                            if (matcher.find()) {
                                authenticatedResults = matcher.group(0)
                            }
                            String authenticatedResults1 = authenticatedResults.replace("LastAuthenticatedResults:", "")
                            Long authenticatedResults2 = Long.valueOf(authenticatedResults1)
                            def lastScan = new Date(authenticatedResults2 * 1000)
                            asset.lastScan = lastScan
                            asset.credentialedScan = true
                            asset.save()
                        } else if (json2.pluginText.contains("Credentialed_Scan:false")) {
                            def matcher = (json2.pluginText =~ /LastUnauthenticatedResults:\d+/)
                            String unauthenticatedResults = ""
                            if (matcher.find()) {
                                unauthenticatedResults = matcher.group(0)
                            }
                            String unauthenticatedResults1 = unauthenticatedResults.replace("LastUnauthenticatedResults:", "")
                            Long unauthenticatedResults2 = Long.valueOf(unauthenticatedResults1)
                            Date lastScan = new Date(unauthenticatedResults2 * 1000)
                            asset.lastScan = lastScan
                            asset.credentialedScan = false
                            asset.save()
                        } else if (json2.pluginText.contains("Credentialed checks : yes")) {
                            String lastSeen1 = json2.lastSeen
                            Long lastSeenLong = Long.valueOf(lastSeen1)
                            asset.lastScan = new Date(lastSeenLong * 1000)
                            asset.credentialedScan = true
                            asset.save()
                        } else if (json2.pluginText.contains("Credentialed checks : no")) {
                            String lastSeen1 = json2.lastSeen
                            Long lastSeenLong = Long.valueOf(lastSeen1)
                            asset.lastScan = new Date(lastSeenLong * 1000)
                            asset.credentialedScan = false
                            asset.save()
                        }
                        else {
                            log.error ("No scan data found for asset: ${asset.name}")
                        }
                    }
                }
            }
        } else {
            log.error("No cookie returned for patch scan checks.")
        }
    }

    @ReadOnly
    def getPatchVulnDetail1 (String vulnDetailId) {
        Long vulnDetailLong = Long.valueOf(vulnDetailId)
        VulnerabilityDetail vulnDetail = VulnerabilityDetail.findWhere(id: vulnDetailLong)
        Map assetMap = ["asset": vulnDetail.asset.name]
        Map assetDescriptionMap = ["assetDescription": vulnDetail.asset.description]
        Map vulnerabilityMap = ["vulnerability": vulnDetail.vulnerability.name]
        Map pluginMap = ["plugin": vulnDetail.vulnerability.plugin]
        Map pluginTextMap = ["pluginText": vulnDetail.pluginText]
        Map solutionMap = ["solution": vulnDetail.solution]
        Map descriptionMap = ["description": vulnDetail.description]
        return (assetMap + vulnerabilityMap + pluginMap + pluginTextMap + descriptionMap +solutionMap + assetDescriptionMap)
    }
}