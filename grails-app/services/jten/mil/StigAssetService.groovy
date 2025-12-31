package jten.mil

import grails.core.GrailsApplication
import grails.gorm.transactions.ReadOnly
import grails.gorm.transactions.Transactional
import groovy.json.JsonSlurper
import groovy.xml.MarkupBuilder
import org.apache.hc.client5.http.classic.methods.HttpPost
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder
import org.apache.hc.core5.http.io.entity.EntityUtils
import org.apache.hc.core5.http.io.entity.StringEntity
import org.apache.hc.core5.ssl.SSLContexts
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

@Transactional
class StigAsset2Service {
    GrailsApplication grailsApplication
    def lookupService

    //returns all StigAsset entries
    @ReadOnly
    def getStigAssets() {
        ArrayList stigAssets = StigAsset.list()
        ArrayList totalStigAssets = []
        if (stigAssets) {
            for (stigAsset in stigAssets) {
                def assetDetailsMap = [
                        "id"         : stigAsset.id,
                        "title"      : stigAsset.stig.title,
                        "releaseInfo": stigAsset.stig.releaseInfo,
                        "version"    : stigAsset.stig.version1,
                        "assetId"    : stigAsset.asset.id,
                        "assetName"  : stigAsset.asset.name,
                        "stigId"     : stigAsset.stig.id,
                        "complete"   : stigAsset.complete,
                        "aor"        : stigAsset.asset.aor.name,
                        "poc"        : stigAsset.asset.poc.name
                ]
                totalStigAssets += assetDetailsMap
            }
            return totalStigAssets
        }
        else {
            return "None"
        }
    }

    def deleteStigAssetCheckValues(def id) {
        def stigAssetValue = StigAsset.findWhere(id: id)
        def stigItemCheckEntries = StigItemCheck.findAllWhere(stigAsset: stigAssetValue)
        if (stigItemCheckEntries) {
            for (entry in stigItemCheckEntries) {
                entry.delete(flush: true)
            }
        }
        def assetStigVulnStatusEntries = AssetStigVulnStatus.findAllWhere(stigAsset: stigAssetValue)
        if (assetStigVulnStatusEntries) {
            for (assetStigVulnStatusEntry in assetStigVulnStatusEntries) {
                assetStigVulnStatusEntry.delete(flush: true)
            }
        }
    }

    def createASVS(StigAsset stigAsset) {
        List<StigVulnerability> stigVulns = StigVulnerability.findAllWhere(stig: stigAsset.stig)
        for (stigVuln in stigVulns) {
            AssetStigVulnStatus assetStigVulnStatus = new AssetStigVulnStatus()
            assetStigVulnStatus.stigVulnerability = stigVuln
            assetStigVulnStatus.asset = stigAsset.asset
            assetStigVulnStatus.stigAsset = stigAsset
            assetStigVulnStatus.status = stigVuln.status
            assetStigVulnStatus.comment = stigVuln.comment
            assetStigVulnStatus.reviewed = false
            try {
                assetStigVulnStatus.save(flush:true)
                if (!assetStigVulnStatus) {
                    assetStigVulnStatus.errors.getAllErrors().each{
                        log.error ("Error: " + it)
                    }
                }
                log.warn ("Created new Asset Stig Vuln Status for asset: ${assetStigVulnStatus.asset.name}")
            } catch (e) {
                log.error (e.getMessage())
            }
        }
        return stigAsset
    }

    @ReadOnly
    def stigSummary() {
        List<Asset> assets = Asset.list()
        ArrayList stigTotal = []
        for (asset in assets) {
            if (asset.stigAsset) {
                def complete = true
                for (entry in asset.stigAsset) {
                    if (!entry.complete) {
                        complete = false
                    }
                }
                def stigDataMap = ["id": asset.id, "asset": asset.name, "complete": complete]
                stigTotal += stigDataMap
            }
        }
        return stigTotal
    }

    def updateSaComplete(String stigAsset) {
        Long stigAssetLong = Long.valueOf(stigAsset)
        StigAsset stigAsset1 = StigAsset.findWhere(id: stigAssetLong)
        List<AssetStigVulnStatus> assetStigVulnStatusValues = AssetStigVulnStatus.findAllWhere(stigAsset: stigAsset1)
        int count = assetStigVulnStatusValues.size()
        Integer counter = 0
        for (entry in assetStigVulnStatusValues) {
            if (entry.reviewed) {
                counter += 1
            }
        }
        if (count > 0) {
            if (counter/count == 1) {
                stigAsset1.complete = true
                stigAsset1.save()
            } else {
                stigAsset1.complete = false
                stigAsset1.save()
            }
        } else {
            stigAsset1.complete = false
            stigAsset1.save()
        }

        return stigAsset1
    }

    @ReadOnly
    def exportSAChecklist(def response1) {
        String zipFileName = grailsApplication.config.getProperty('tempLocation', String.class)+"zipFile/StigAssets.zip"
        String inputDir = grailsApplication.config.getProperty('tempLocation', String.class)+"input"
        def stigAssets = response1.stigAsset
        for (stigAsset in stigAssets) {
            String stigAssetString = stigAsset.toString()
            StigAsset stigAsset1 = StigAsset.findWhere(id: Long.valueOf(stigAssetString))
            generateAssetStigFile(stigAsset1)
        }
        ZipOutputStream zipFile = new ZipOutputStream(new FileOutputStream(zipFileName))
        new File(inputDir).eachFile() { file ->
            //check if file
            if (file.isFile()) {
                zipFile.putNextEntry(new ZipEntry(file.name))
                def buffer = new byte[file.size()]
                file.withInputStream {
                    zipFile.write(buffer, 0, it.read(buffer))
                }
                zipFile.closeEntry()
            }
        }
        zipFile.close()
    }

    @ReadOnly
    def generateAssetStigFile(StigAsset stigAsset1) {
        def xmlWriter = new StringWriter()
        def xmlMarkup = new MarkupBuilder(xmlWriter)
        String xmlHeaderString = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        String xmlHeaderString2 = "<!--DISA STIG Viewer :: 2.17-->"
        xmlMarkup.CHECKLIST {
            ASSET {
                ROLE("${stigAsset1.asset.role}")
                ASSET_TYPE("${stigAsset1.asset.assetType}")
                HOST_NAME("${stigAsset1.asset.name}")
                HOST_IP("${stigAsset1.asset.ipAddress}")
                if (stigAsset1.asset.macAddress) {
                    HOST_MAC("${stigAsset1.asset.macAddress}")
                } else {
                    HOST_MAC()
                }
                HOST_FQDN("${stigAsset1.asset.name}")
                TECH_AREA("${stigAsset1.asset.techArea}")
                TARGET_KEY()
                WEB_OR_DATABASE("${stigAsset1.asset.webOrDatabase}")
                if (stigAsset1.asset.webOrDatabaseSite) {
                    WEB_DB_SITE("${stigAsset1.asset.webOrDatabaseSite}")
                } else {
                    WEB_DB_SITE()
                }
                if (stigAsset1.asset.webOrDatabaseInstance) {
                    WEB_DB_INSTANCE("${stigAsset1.asset.webOrDatabaseInstance}")
                } else {
                    WEB_DB_INSTANCE()
                }
            }
            STIGS {
                iSTIG {
                    STIG_INFO {
                        SI_DATA {
                            SID_NAME("version")
                            SID_DATA("${stigAsset1.stig.version1}")
                        }
                        SI_DATA {
                            SID_NAME("classification")
                            SID_DATA("${stigAsset1.stig.classification}")
                        }
                        if (stigAsset1.stig.customName) {
                            SI_DATA {
                                SID_NAME("customname")
                                SID_DATA("${stigAsset1.stig.customName}")
                            }
                        } else {
                            SI_DATA {
                                SID_NAME("customname")
                                SID_DATA()
                            }
                        }
                        SI_DATA {
                            SID_NAME("stigid")
                            SID_DATA("${stigAsset1.stig.stigId}")
                        }
                        SI_DATA {
                            SID_NAME("description")
                            SID_DATA("${stigAsset1.stig.description}")
                        }
                        SI_DATA {
                            SID_NAME("filename")
                            SID_DATA("${stigAsset1.stig.fileName}")
                        }
                        if (stigAsset1.stig.releaseInfo) {
                            SI_DATA {
                                SID_NAME("releaseinfo")
                                SID_DATA("${stigAsset1.stig.releaseInfo}")
                            }
                        } else {
                            SI_DATA {
                                SID_NAME("releaseinfo")
                                SID_DATA()
                            }
                        }
                        SI_DATA {
                            SID_NAME("title")
                            SID_DATA("${stigAsset1.stig.title}")
                        }
                        SI_DATA {
                            SID_NAME("uuid")
                            SID_DATA("${stigAsset1.stig.uuid}")
                        }
                        SI_DATA {
                            SID_NAME("notice")
                            SID_DATA("${stigAsset1.stig.notice}")
                        }
                        if (stigAsset1.stig.source) {
                            SI_DATA {
                                SID_NAME("source")
                                SID_DATA("${stigAsset1.stig.source}")
                            }
                        } else {
                            SI_DATA {
                                SID_NAME("source")
                                SID_DATA()
                            }
                        }
                    }
                    List<StigVulnerability> stigVulns = StigVulnerability.findAllWhere(stig: stigAsset1.stig)
                    for (stigVuln in stigVulns) {
                        VULN {
                            STIG_DATA {
                                VULN_ATTRIBUTE("Vuln_Num")
                                ATTRIBUTE_DATA("${stigVuln.vulnNum}")
                            }
                            STIG_DATA {
                                VULN_ATTRIBUTE("Severity")
                                ATTRIBUTE_DATA("${stigVuln.severity}")
                            }
                            STIG_DATA {
                                VULN_ATTRIBUTE("Group_Title")
                                ATTRIBUTE_DATA("${stigVuln.groupTitle}")
                            }
                            STIG_DATA {
                                VULN_ATTRIBUTE("Rule_ID")
                                ATTRIBUTE_DATA("${stigVuln.ruleId}")
                            }
                            STIG_DATA {
                                VULN_ATTRIBUTE("Rule_Ver")
                                ATTRIBUTE_DATA("${stigVuln.ruleVer}")
                            }
                            STIG_DATA {
                                VULN_ATTRIBUTE("Rule_Title")
                                ATTRIBUTE_DATA("${stigVuln.ruleTitle}")
                            }
                            STIG_DATA {
                                VULN_ATTRIBUTE("Vuln_Discuss")
                                ATTRIBUTE_DATA("${stigVuln.vulnDiscuss}")
                            }
                            if (stigVuln.iaControls) {
                                STIG_DATA {
                                    VULN_ATTRIBUTE("IA_Controls")
                                    ATTRIBUTE_DATA("${stigVuln.iaControls}")
                                }
                            } else {
                                STIG_DATA {
                                    VULN_ATTRIBUTE("IA_Controls")
                                    ATTRIBUTE_DATA()
                                }
                            }
                            STIG_DATA {
                                VULN_ATTRIBUTE("Check_Content")
                                ATTRIBUTE_DATA("${stigVuln.checkContent}")
                            }
                            STIG_DATA {
                                VULN_ATTRIBUTE("Fix_Text")
                                ATTRIBUTE_DATA("${stigVuln.fixText}")
                            }
                            STIG_DATA {
                                VULN_ATTRIBUTE("False_Positives")
                                ATTRIBUTE_DATA()
                            }
                            STIG_DATA {
                                VULN_ATTRIBUTE("False_Negatives")
                                ATTRIBUTE_DATA()
                            }
                            STIG_DATA {
                                VULN_ATTRIBUTE("Documentable")
                                ATTRIBUTE_DATA()
                            }
                            STIG_DATA {
                                VULN_ATTRIBUTE("Mitigations")
                                ATTRIBUTE_DATA()
                            }
                            STIG_DATA {
                                VULN_ATTRIBUTE("Third_Party_Tools")
                                ATTRIBUTE_DATA()
                            }
                            STIG_DATA {
                                VULN_ATTRIBUTE("Mitigation_Control")
                                ATTRIBUTE_DATA()
                            }
                            STIG_DATA {
                                VULN_ATTRIBUTE("Responsibility")
                                ATTRIBUTE_DATA("${stigVuln.responsibility}")
                            }
                            STIG_DATA {
                                VULN_ATTRIBUTE("Security_Override_Guidance")
                                ATTRIBUTE_DATA()
                            }
                            if (stigVuln.checkContentRef) {
                                STIG_DATA {
                                    VULN_ATTRIBUTE("Check_Content_Ref")
                                    ATTRIBUTE_DATA("${stigVuln.checkContentRef}")
                                }
                            } else {
                                STIG_DATA {
                                    VULN_ATTRIBUTE("Check_Content_Ref")
                                    ATTRIBUTE_DATA()
                                }
                            }
                            if (stigVuln.weight) {
                                STIG_DATA {
                                    VULN_ATTRIBUTE("Weight")
                                    ATTRIBUTE_DATA("${stigVuln.weight}")
                                }
                            } else {
                                STIG_DATA {
                                    VULN_ATTRIBUTE("Weight")
                                    ATTRIBUTE_DATA()
                                }
                            }
                            STIG_DATA {
                                VULN_ATTRIBUTE("Class")
                                ATTRIBUTE_DATA("${stigVuln.class1}")
                            }
                            STIG_DATA {
                                VULN_ATTRIBUTE("STIGRef")
                                ATTRIBUTE_DATA("${stigVuln.stigRef}")
                            }
                            STIG_DATA {
                                VULN_ATTRIBUTE("TargetKey")
                                ATTRIBUTE_DATA("${stigVuln.targetKey}")
                            }
                            if (stigVuln.cciRef) {
                                STIG_DATA {
                                    VULN_ATTRIBUTE("CCI_REF")
                                    ATTRIBUTE_DATA("${stigVuln.cciRef}")
                                }
                            } else {
                                STIG_DATA {
                                    VULN_ATTRIBUTE("CCI_REF")
                                    ATTRIBUTE_DATA()
                                }
                            }
                            AssetStigVulnStatus assetStigVulnStatus = AssetStigVulnStatus.findWhere(stigAsset: stigAsset1, stigVulnerability: stigVuln)
                            def statusMapping = [
                                    "nf"            : "NotAFinding",
                                    "na"            : "Not_Applicable",
                                    "nr"            : "Not_Reviewed",
                                    "not_reviewed"  : "Not_Reviewed",
                                    "not_applicable": "Not_Applicable",
                                    "notafinding"   : "NotAFinding"
                            ]

                            if (assetStigVulnStatus) {
                                String statusToApply = assetStigVulnStatus.status.toLowerCase()
                                if (statusMapping.containsKey(statusToApply)) {
                                    STATUS(statusMapping[statusToApply])
                                } else {
                                    STATUS("Open")
                                }
                            } else {
                                STATUS("Not_Reviewed")
                            }
                            FINDING_DETAILS()
                            StigVulnerability stigVulnerability = assetStigVulnStatus.stigVulnerability
                            MitigationStig mitStig = MitigationStig.findWhere(aor: assetStigVulnStatus.asset.aor, stigVulnerability: stigVulnerability)
                            if (assetStigVulnStatus.customStigMit) {
                                def comment = "Mitigation Strategy: ${assetStigVulnStatus.customStigMit.mitType} \n" +
                                        "Completion Date: ${assetStigVulnStatus.customStigMit.completeDate} \n" +
                                        "Comments: ${assetStigVulnStatus.customStigMit.mitComment} \n" +
                                        "Milestones: ${assetStigVulnStatus.customStigMit.milestone} \n" +
                                        "Milestone Changes: ${assetStigVulnStatus.customStigMit.milestoneChange} \n" +
                                        "Resources Required: ${assetStigVulnStatus.customStigMit.resourcesRequired} \n" +
                                        "ISSE: ${assetStigVulnStatus.asset.aor.isse}"
                                COMMENTS(comment)
                            }
                            else if (mitStig) {
                                def comment = "Mitigation Strategy: ${mitStig.mitType} \n" +
                                        "Completion Date: ${mitStig.completeDate} \n" +
                                        "Comments: ${mitStig.mitComment} \n" +
                                        "Milestones: ${mitStig.milestone} \n" +
                                        "Milestone Changes: ${mitStig.milestoneChange} \n" +
                                        "Resources Required: ${mitStig.resourcesRequired} \n" +
                                        "ISSE: ${mitStig.aor.isse}"
                                COMMENTS(comment)
                            } else if (assetStigVulnStatus.comment) {
                                COMMENTS("${assetStigVulnStatus.comment}")
                            } else {
                                COMMENTS("NA")
                            }
                            SEVERITY_OVERRIDE()
                            SEVERITY_JUSTIFICATION()
                        }
                    }
                }
            }
        }
        File file = new File(grailsApplication.config.getProperty('tempLocation', String.class)+"input/" + stigAsset1.stig.title + " for asset " + stigAsset1.asset.name + ".ckl")
        file.write(xmlHeaderString + "\n" + xmlHeaderString2 + "\n" + xmlWriter.toString())
    }

    //Retrieves posture of all assets identified with field "posture" true
    def getPosture(Map map){
        String token = "${map.get("token")}"
        String cookie = "${map.get("cookie")}"
        if (cookie != "null") {
            String repositories = (grailsApplication.config.getProperty('acasAuditRepository', String.class))
            def sslContext = SSLContexts.createSystemDefault()
            List<Asset> assets = Asset.findAllWhere(posture: true)
            for (asset in assets) {
                String json = ""
                def query = '{ ' +
                        '"query": {' +
                        '"type":"vuln",' +
                        '"tool":"vulndetails",' +
                        '"filters": [{' +
                        '"id":"repository", ' +
                        '"filterName":"repositoryIDs",' +
                        '"operator":"=",' +
                        '"value":"' + repositories + '"' +
                        '},' +
                        '{"id":"familyID", ' +
                        '"filterName":"familyID",' +
                        '"operator":"=",' +
                        '"value":"0"' +
                        '},' +
                        '{"id":"ip", ' +
                        '"filterName":"ip",' +
                        '"operator":"=",' +
                        '"value":"' + asset.ipAddress + '"' +
                        '}' +
                        ']' +
                        '},' +
                        '"type":"vuln", ' +
                        '"tool":"vulndetails", ' +
                        '"sourceType":"cumulative", ' +
                        '"startOffset":0, ' +
                        '"endOffset":2000' +
                        '}'
                def uri = grailsApplication.config.getProperty('acasUrl', String.class) + '/rest/analysis'
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
                    log.error "Failed retrieving asset list"
                } finally {
                    httpClient.close()
                }
                def jsonSlurper = new JsonSlurper()
                def json1 = jsonSlurper.parseText(json)
                try {
                    List<String> results = json1.response.results
                    results.each { result ->
                        if (result.family.name == "N/A") {
                            if (result.pluginText.contains("<cm:compliance-actual-value>")) {
                                String xref = result.xref
                                String[] vulnNumArray = xref.split(",")
                                String tenable = ""
                                for (entry in vulnNumArray) {
                                    if (entry.startsWith("DISA_Benchmark")) {
                                        tenable = entry.replaceAll("DISA_Benchmark #", "")
                                    }
                                }

                                if (tenable) {
                                    Stig stig = Stig.findWhere(tenable: tenable)
                                    if (stig) {
                                        StigAsset stigAsset2 = StigAsset.findWhere(asset: asset, stig:stig)
                                        if (!stigAsset2) {
                                            log.warn("Tenable: " + tenable)
                                            log.warn ("Adding STIG Asset for STIG: ${stig.title} and asset: ${asset.name}")
                                            def stigAsset = new StigAsset( asset: asset, stig: stig).save(flush:true)
                                            def stigVulnerabilities = StigVulnerability.findAllWhere(stig: stig)
                                            for (stigVulnerability in stigVulnerabilities){
                                                def assetStigVulnStatus = new AssetStigVulnStatus(stigVulnerability: stigVulnerability, asset: asset, stigAsset: stigAsset, status: stigVulnerability.status, comment: stigVulnerability.comment)
                                                assetStigVulnStatus.save()
                                            }
                                        }
                                    }
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

    //get Posture for one asset
    @Transactional
    def getPosture1(Map map, String id){
        String token = "${map.get("token")}"
        String cookie = "${map.get("cookie")}"
        if (cookie != "null") {
            String repositories = (grailsApplication.config.getProperty('acasAuditRepository', String.class))
            def sslContext = SSLContexts.createSystemDefault()
            String json = ""
            Long idLong = Long.valueOf(id)
            Asset asset = Asset.findWhere(id: idLong)
            def query = '{ ' +
                    '"query": {' +
                    '"type":"vuln",' +
                    '"tool":"vulndetails",' +
                    '"filters": [{' +
                    '"id":"repository", ' +
                    '"filterName":"repositoryIDs",' +
                    '"operator":"=",' +
                    '"value":"' + repositories + '"' +
                    '},' +
                    '{"id":"familyID", ' +
                    '"filterName":"familyID",' +
                    '"operator":"=",' +
                    '"value":"0"' +
                    '},' +
                    '{"id":"ip", ' +
                    '"filterName":"ip",' +
                    '"operator":"=",' +
                    '"value":"' + asset.ipAddress + '"' +
                    '}' +
                    ']' +
                    '},' +
                    '"type":"vuln", ' +
                    '"tool":"vulndetails", ' +
                    '"sourceType":"cumulative", ' +
                    '"startOffset":0, ' +
                    '"endOffset":2000' +
                    '}'
            def uri = grailsApplication.config.getProperty('acasUrl', String.class) + '/rest/analysis'
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
                log.error "Failed retrieving asset list"
            } finally {
                httpClient.close()
            }
            def jsonSlurper = new JsonSlurper()
            def json1 = jsonSlurper.parseText(json)
            try {
                List<String> results = json1.response.results
                results.each { result ->
                    if (result.family.name == "N/A") {
                        if (result.pluginText.contains("<cm:compliance-actual-value>")) {
                            String xref = result.xref
                            String[] vulnNumArray = xref.split(",")
                            String tenable = ""
                            for (entry in vulnNumArray) {
                                if (entry.startsWith("DISA_Benchmark")) {
                                    tenable = entry.replaceAll("DISA_Benchmark #", "")
                                }
                            }

                            if (tenable) {
                                Stig stig = Stig.findWhere(tenable: tenable)
                                if (stig) {
                                    StigAsset stigAsset2 = StigAsset.findWhere(asset: asset, stig:stig)
                                    if (!stigAsset2) {
                                        log.warn("Tenable: " + tenable)
                                        log.warn ("Adding STIG Asset for STIG: ${stig.title} and asset: ${asset.name}")
                                        def stigAsset = new StigAsset( asset: asset, stig: stig).save(flush:true)
                                        def stigVulnerabilities = StigVulnerability.findAllWhere(stig: stig)
                                        for (stigVulnerability in stigVulnerabilities){
                                            def assetStigVulnStatus = new AssetStigVulnStatus(stigVulnerability: stigVulnerability, asset: asset, stigAsset: stigAsset, status: stigVulnerability.status, comment: stigVulnerability.comment)
                                            assetStigVulnStatus.save()
                                        }
                                    }
                                }
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
