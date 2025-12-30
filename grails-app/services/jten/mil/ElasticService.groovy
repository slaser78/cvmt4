package jten.mil


import grails.core.GrailsApplication
import grails.gorm.transactions.Transactional
import groovy.json.JsonOutput
import org.apache.hc.client5.http.classic.methods.HttpPost
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient
import org.apache.hc.client5.http.impl.classic.HttpClients
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder
import org.apache.hc.core5.http.io.entity.EntityUtils
import org.apache.hc.core5.http.io.entity.StringEntity
import org.apache.hc.core5.ssl.SSLContexts

@Transactional
class ElasticService {
    def lookupService
    GrailsApplication grailsApplication

    def elasticPatchUpload() {
        List<VulnerabilityDetail> vulnerabilityDetails = VulnerabilityDetail.findAll()
        if (vulnerabilityDetails) {
            vulnerabilityDetails.each { VulnerabilityDetail vulnerabilityDetail ->
                Map timestamp = ["@timestamp": new Date().format("yyyy-MM-dd")]
                Map vulnerabilityName = ["Vulnerability": vulnerabilityDetail.vulnerability.name]
                Map vulnerabilityPlugin = ["Plugin": vulnerabilityDetail.vulnerability.plugin]
                Map vulnerabilityFirstSeen = ["First Seen": vulnerabilityDetail.firstSeen.format("yyyy-MM-dd")]
                Map stigSeverity = ["STIG Severity": vulnerabilityDetail.vulnerability.stigSeverity]
                Map severity = ["Severity": vulnerabilityDetail.vulnerability.severity]
                Map exploitable = ["Exploitable": vulnerabilityDetail.vulnerability.exploitable]
                Map asset = ["Asset": vulnerabilityDetail.asset.name]
                Map ipAddress = ["IP Address": vulnerabilityDetail.asset.ipAddress]
                Map suspenseDate = ["Suspense Date": vulnerabilityDetail.suspenseDate.format("yyyy-MM-dd")]
                Map aor = ["AOR": vulnerabilityDetail.asset.aor.name]
                Map poc = ["POC": vulnerabilityDetail.asset.poc.name]
                Map crit = ["Critical": vulnerabilityDetail.asset.crit]
                Map por = ["PoR": vulnerabilityDetail.asset.por]
                Map cve = ["CVE": vulnerabilityDetail.vulnerability.cve]
                Map suspense
                if (vulnerabilityDetail.suspense == "one" || vulnerabilityDetail.suspense == "two"){
                    suspense = ["Suspense": false]
                } else {
                    suspense = ["Suspense": true]
                }
                Map family = ["Family": vulnerabilityDetail.vulnerability.family]
                Mitigation poam = Mitigation.findWhere(aor: vulnerabilityDetail.asset.aor, vulnerability: vulnerabilityDetail.vulnerability, mitType: "POAM")
                CustomPatchMit customPatchMit = CustomPatchMit.findWhere(vulnerabilityDetail: vulnerabilityDetail, mitType: "POAM")
                Map milestones
                Map milestoneChanges
                Map resourcesRequired
                Map completeDate
                Map type

                if (customPatchMit) {
                    milestones = ["Milestones": customPatchMit.milestone]
                    milestoneChanges = ["Milestone Changes": customPatchMit.milestoneChange]
                    resourcesRequired = ["Resources Required": customPatchMit.resourcesRequired]
                    completeDate = ["Completion Date": customPatchMit.completeDate.format("yyyy-MM-dd")]
                    type = ["Type": "Custom"]
                }
                else if (poam) {
                    milestones = ["Milestones": poam.milestone]
                    milestoneChanges = ["Milestone Changes": poam.milestoneChange]
                    resourcesRequired = ["Resources Required": poam.resourcesRequired]
                    completeDate = ["Completion Date": poam.completeDate.format("yyyy-MM-dd")]
                    type = ["Type": "AOR"]
                } else {
                    milestones = ["Milestones": "NA"]
                    milestoneChanges = ["Milestone Changes": "NA"]
                    resourcesRequired = ["Resources Required": "NA"]
                    completeDate = ["Completion Date": "NA"]
                    type = ["Type": "None"]
                }
                String body = JsonOutput.toJson(timestamp + vulnerabilityName + vulnerabilityPlugin + vulnerabilityFirstSeen +
                        severity + exploitable + asset + ipAddress + resourcesRequired + milestoneChanges + milestones +
                        completeDate + aor + poc + type + stigSeverity + suspenseDate + crit + por + suspense + family + cve)

                String uri = grailsApplication.config.getProperty('elasticUrl', String.class) + "/cvmt-patch-datastream/_doc"

                def sslContext1 = lookupService.getSslContext()

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
                String json = null
                try {
                    HttpPost httpPost = new HttpPost(uri)
                    httpPost.addHeader("Content-Type", "application/json")
                    httpPost.addHeader("Authorization", "ApiKey " + grailsApplication.config.getProperty('elasticApiKey', String.class))
                    StringEntity entity = new StringEntity(body)
                    httpPost.setEntity(entity)
                    HttpClientContext clientContext = HttpClientContext.create()
                    httpClient.execute(httpPost, clientContext, response -> {
                        json = EntityUtils.toString(response.getEntity())
                    })
                } catch (e) {
                    log.error(e.getMessage())
                    log.error("Asset: ${vulnerabilityDetail.asset.name} has error uploading to Elastic:")
                } finally {
                    httpClient.close()
                }
            }
        } else {
            log.error ("No Vulnerability Details found.")
        }
    }

    def elasticStigUpload() {
        List<AssetStigVulnStatus> assetStigVulnStatuses = AssetStigVulnStatus.findAllWhere(status: "Open")
        if (assetStigVulnStatuses) {
            SSLContext sslContext = lookupService.getSslContext()
            assetStigVulnStatuses.each { AssetStigVulnStatus assetStigVulnStatus ->
                Map timestamp = ["@timestamp": new Date().format("yyyy-MM-dd")]
                Map vulnerability = ["Vulnerability": assetStigVulnStatus.stigVulnerability.ruleTitle]
                Map number = ["Number": assetStigVulnStatus.stigVulnerability.vulnNum]
                Map firstSeen = ["First Seen": assetStigVulnStatus.firstSeen.format("yyyy-MM-dd")]
                Map severity = ["Severity": assetStigVulnStatus.stigVulnerability.severity]
                Map asset = ["Asset": assetStigVulnStatus.asset.name]
                Map ipAddress = ["IP Address": assetStigVulnStatus.asset.ipAddress]
                Map poc = ["POC": assetStigVulnStatus.asset.poc.name]
                Map aor = ["AOR": assetStigVulnStatus.asset.aor.name]
                Map crit = ["Critical": assetStigVulnStatus.asset.crit]
                Map por = ["PoR": assetStigVulnStatus.asset.por]
                MitigationStig poam = MitigationStig.findWhere(stigVulnerability: assetStigVulnStatus.stigVulnerability, aor: assetStigVulnStatus.asset.aor, mitType: "POAM")
                CustomStigMit customStigMit = CustomStigMit.findWhere(assetStigVulnStatus: assetStigVulnStatus)
                Map milestones
                Map milestoneChanges
                Map resourcesRequired
                Map completeDate
                Map type
                if (customStigMit) {
                    completeDate = ["Completion Date": customStigMit.createDate.format("yyyy-MM-dd")]
                    milestones = ["Milestones": customStigMit.milestone]
                    milestoneChanges = ["Milestone Changes": customStigMit.milestoneChange]
                    resourcesRequired = ["Resources Required": customStigMit.resourcesRequired]
                    type = ["Type": "Custom"]
                }
                else if (poam) {
                    milestones = ["Milestones": poam.milestone]
                    milestoneChanges = ["Milestone Changes": poam.milestoneChange]
                    resourcesRequired = ["Resources Required": poam.resourcesRequired]
                    completeDate = ["Completion Date": poam.completeDate.format("yyyy-MM-dd")]
                    type = ["Type": "AOR"]
                }
                else {
                    milestones = ["Milestones": "NA"]
                    milestoneChanges = ["Milestone Changes": "NA"]
                    resourcesRequired = ["Resources Required": "NA"]
                    completeDate = ["Completion Date": "NA"]
                    type = ["Type": "None"]
                }
                String body = JsonOutput.toJson(timestamp + vulnerability + number + firstSeen + severity + type +
                        asset + ipAddress + completeDate + aor + poc + milestones + milestoneChanges + resourcesRequired + crit + por)
                String uri = grailsApplication.config.getProperty('elasticUrl', String.class) + "/cvmt-stig-datastream/_doc"
                Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory> create()
                        .register("https", new SSLConnectionSocketFactory(sslContext))
                        .build()
                CloseableHttpClient httpClient = HttpClientBuilder.create()
                        .setConnectionManager(new PoolingHttpClientConnectionManager(registry))
                        .build()
                String json = null
                try {
                    HttpPost httpPost = new HttpPost(uri)
                    httpPost.addHeader("Content-Type", "application/json")
                    httpPost.addHeader("Authorization", "ApiKey " + grailsApplication.config.getProperty('elasticApiKey', String.class))
                    StringEntity entity = new StringEntity(body)
                    httpPost.setEntity(entity)
                    HttpClientContext clientContext = HttpClientContext.create()
                    httpClient.execute(httpPost, clientContext, response -> {
                        json = EntityUtils.toString(response.getEntity())
                    })
                } catch (e) {
                    log.error(e.getMessage())
                    log.error("Asset: ${assetStigVulnStatus.asset.name} has error uploading to Elastic:")
                } finally {
                    httpClient.close()
                }
            }
        } else {
            log.error ("No Vulnerability Details found.")
        }
    }

    def elasticAssetUpload () {
        List<Asset> assets = Asset.list()
        if (assets) {
            SSLContext sslContext = lookupService.getSslContext()
            for (asset in assets) {
                if (asset.ipAddress != "None") {
                    Map timestamp = ["@timestamp": new Date().format("yyyy-MM-dd")]
                    Map asset1 = ["Name": asset.name]
                    Map ipAddress = ["IP Address ": asset.ipAddress]
                    Map description
                    if (asset.description) {
                        description = ["Description": asset.description]
                    } else {
                        description = ["Description": "NA"]
                    }
                    Map poc = ["POC": asset.poc.name]
                    Map aor = ["AOR": asset.aor.name]
                    Map score
                    if (asset.score) {
                        score = ["Score": asset.score]
                    } else {
                        score = ["Score": "NA"]
                    }
                    Map lastScan
                    if (asset.lastScan) {
                        lastScan = ["Last Scan": asset.lastScan.format("yyyy-MM-dd")]
                    } else {
                        lastScan = ["Last Scan": "NA"]
                    }
                    Map subnet = ["Subnet": asset.subnet.subnet]
                    Map operatingSystem = ["Operating System": asset.opSystem]
                    Map credentialedScan = ["Credentialed Scan": asset.credentialedScan]
                    String body = JsonOutput.toJson(timestamp + asset1 + ipAddress + score + operatingSystem +
                            poc + aor + credentialedScan + lastScan + description + subnet)
                    String uri = grailsApplication.config.getProperty('elasticUrl', String.class) + "/cvmt-asset-datastream/_doc"
                    Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory> create()
                            .register("https", new SSLConnectionSocketFactory(sslContext))
                            .build()
                    CloseableHttpClient httpClient = HttpClientBuilder.create()
                            .setConnectionManager(new PoolingHttpClientConnectionManager(registry))
                            .build()
                    String json = null
                    try {
                        HttpPost httpPost = new HttpPost(uri)
                        httpPost.addHeader("Content-Type", "application/json")
                        httpPost.addHeader("Authorization", "ApiKey " + grailsApplication.config.getProperty('elasticApiKey', String.class))
                        StringEntity entity = new StringEntity(body)
                        httpPost.setEntity(entity)
                        HttpClientContext clientContext = HttpClientContext.create()
                        httpClient.execute(httpPost, clientContext, response -> {
                            json = EntityUtils.toString(response.getEntity())
                        })
                    } catch (e) {
                        log.error(e.getMessage())
                        log.error("Asset: ${asset.name} has error uploading to Elastic.")
                    } finally {
                        httpClient.close()
                    }
                }
            }
        } else {
            log.error("No assets found.")
        }
    }

    def elasticDeviceTypeUpload() {
        List<Asset> assets = Asset.list()
        String uri = grailsApplication.config.getProperty('elasticUrl', String.class) + "/cvmt-stig-summary-datastream/_doc"
        for (asset in assets) {
            if (asset.deviceType) {
                SSLContext sslContext = lookupService.getSslContext()
                Map assetOS = ["Asset Operating System": asset.deviceType]
                Map timestamp = ["@timestamp": new Date().format("yyyy-MM-dd")]
                List<AssetStigVulnStatus> assetStigVulnStatuses = AssetStigVulnStatus.findAllWhere(asset: asset)
                def openCount = 0
                Map assetName = ["Asset Name": asset.name]
                Map assetIpAddress = ["Asset IP Address": asset.ipAddress]
                for (assetStigVulnStatus in assetStigVulnStatuses) {
                    if (assetStigVulnStatus.status == "Open") {
                        openCount = openCount + 1
                    }
                }
                def assetStigVulnStatusCount = assetStigVulnStatuses.size()
                if (assetStigVulnStatusCount > 0) {
                    Integer pass = (assetStigVulnStatusCount - openCount)
                    Map pass1 = ["Pass": pass.toString()]
                    Map fail = ["Fail": openCount.toString()]
                    Map compliance = ["Compliance": (pass / assetStigVulnStatusCount).toString()]
                    String body = JsonOutput.toJson(timestamp + assetOS + pass1 + fail + compliance + assetName + assetIpAddress)
                    Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory> create()
                            .register("https", new SSLConnectionSocketFactory(sslContext))
                            .build()
                    CloseableHttpClient httpClient = HttpClientBuilder.create()
                            .setConnectionManager(new PoolingHttpClientConnectionManager(registry))
                            .build()
                    String json = null
                    try {
                        HttpPost httpPost = new HttpPost(uri)
                        httpPost.addHeader("Content-Type", "application/json")
                        httpPost.addHeader("Authorization", "ApiKey " + grailsApplication.config.getProperty('elasticApiKey', String.class))
                        StringEntity entity = new StringEntity(body)
                        httpPost.setEntity(entity)
                        HttpClientContext clientContext = HttpClientContext.create()
                        httpClient.execute(httpPost, clientContext, response -> {
                            json = EntityUtils.toString(response.getEntity())
                        })
                    } catch (e) {
                        log.error(e.getMessage())
                        log.error("Operating System STIG Summary has error uploading to Elastic:")
                    } finally {
                        httpClient.close()
                    }
                }
            }
        }
    }
}