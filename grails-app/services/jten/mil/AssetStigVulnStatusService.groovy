package jten.mil

import grails.gorm.transactions.ReadOnly
import grails.gorm.transactions.Transactional
import groovy.xml.XmlSlurper
import groovy.xml.slurpersupport.GPathResult

@Transactional
class AssetStigVulnStatusService {
    def asvsFilterService
    def asvsSortService

    //get AssetStigVulnStatusEntry using stigVulnerability and stigAsset values
    def getAssetStigVulnStatusEntry(def stigVuln, def stigAsset) {
        String stigVulnString = stigVuln.toString()
        Long stigVulnLong = Long.valueOf(stigVulnString)
        StigVulnerability stigVulnValue = StigVulnerability.findWhere(id: stigVulnLong)
        String stigAssetString = stigAsset.toString()
        Long stigAssetLong = Long.valueOf(stigAssetString)
        StigAsset stigAssetValue = StigAsset.findWhere(id:stigAssetLong)
        AssetStigVulnStatus assetStigVulnStatusValue = AssetStigVulnStatus.findWhere(stigAsset: stigAssetValue, stigVulnerability:stigVulnValue )
        return assetStigVulnStatusValue
    }

    //get assetStigVulnStatus entries for one STIG-Asset
    static final String TRUE_FLAG = "true"
    def getAssetStigVulnStatusEntries(String statusAssetId) {
        def parsedAssetId = Long.valueOf(statusAssetId)
        def stigAssetRequested = StigAsset.findWhere(id: parsedAssetId)
        def stigVulnerabilitiesList = StigVulnerability.findAllWhere(stig: stigAssetRequested.stig)
        def securityStatusList = AssetStigVulnStatus.findAllWhere(stigAsset: stigAssetRequested)
        def combinedStigVulnList = []
        securityStatusList.each { combinedStigVulnList += it.stigVulnerability }
        combinedStigVulnList.intersect(stigVulnerabilitiesList).each {
            combinedStigVulnList.remove(it)
            stigVulnerabilitiesList.remove(it)
        }
        manageSecurityStatusEntries(combinedStigVulnList, stigVulnerabilitiesList, stigAssetRequested)
        return fetchTotalSecurityStatus(stigAssetRequested)
    }

    def manageSecurityStatusEntries(def combinedStigVulnList, def stigVulnerabilitiesList, def stigAssetRequested) {
        if (combinedStigVulnList.size() > 0) {
            combinedStigVulnList.each {
                def statusEntry = AssetStigVulnStatus.findWhere(stigVulnerability: it, asset: stigAssetRequested.asset, stigAsset: stigAssetRequested)
                statusEntry.delete(flush: TRUE_FLAG)
            }
        } else if (stigVulnerabilitiesList.size() > 0) {
            stigVulnerabilitiesList.each {
                new AssetStigVulnStatus(stigAsset: stigAssetRequested, stigVulnerability: it, asset: stigAssetRequested.asset, comment: it.comment, status: it.status)
                        .save(flush: TRUE_FLAG)
            }
        }
    }

    def fetchTotalSecurityStatus(def stigAssetRequested) {
        def totalSecurityStatus = []
        def fetchedStatusList = AssetStigVulnStatus.findAllWhere(stigAsset: stigAssetRequested)
        fetchedStatusList.each {
            totalSecurityStatus +=
                    ['id'          : it.id,
                     'vulnNum'     : it.stigVulnerability.vulnNum,
                     'ruleTitle'   : it.stigVulnerability.ruleTitle,
                     'comment'     : it.comment,
                     'status'      : it.status,
                     'reviewed'    : it.reviewed,
                     'checkContent': it.stigVulnerability.checkContent,
                     'fixText'     : it.stigVulnerability.fixText,
                     'vulnDiscuss' : it.stigVulnerability.vulnDiscuss,
                     'severity'    : it.stigVulnerability.severity,
                     'asset'       : it.asset.name,
                     'stig'        : it.stigVulnerability.stig.title]
        }
        def totalSecurityStatus1 = ["totalSecurityStatus": totalSecurityStatus]
        def asset = ["asset" : fetchedStatusList[0].asset.name]
        def stig = ["stig": fetchedStatusList[0].stigVulnerability.stig.title]

        return totalSecurityStatus1 + asset + stig
    }

    //update assetStigVulnStatus "reviewed" field
    def setAssetStigVulnStatusEntry(def request) {
        String reviewed = request.reviewed
        String requestIdString = request.id.toString()
        Long idLong = Long.valueOf(requestIdString)
        AssetStigVulnStatus assetStigVulnStatus = AssetStigVulnStatus.findWhere(id: idLong)
        assetStigVulnStatus.reviewed = reviewed.toBoolean()
        assetStigVulnStatus.save()
        return assetStigVulnStatus
    }

    @ReadOnly
    def getAsvsCount(def params) {
        def filterModelEntries = (params.filterModel)
        List<AssetStigVulnStatus> assetStigVulnStatusValues = AssetStigVulnStatus.findAllWhere (status: "Open")
        List<MitigationStig> mitigationStigs = MitigationStig.list()
        List<CustomStigMit> customStigMits = CustomStigMit.list()
        ArrayList asvsFiltered = asvsFilterService.filterModel(assetStigVulnStatusValues, filterModelEntries, mitigationStigs, customStigMits)
        return asvsFiltered.size()
    }

    //get ALL assetStigVulnStatus entries where status = "Open"
    @ReadOnly
    def getAssetStigVulnStatuses(def params) {
        ArrayList vulnTotal = []
        //  Fetch all open AssetStigVulnStatus records eagerly along with relational data at once
        def pageInteger = (params.page).toInteger()
        def pageSizeInteger = (params.pageSize).toInteger()
        def filterModelEntries = params.filterModel
        def sortModelEntry = params.sortModel
        int indexStart = pageSizeInteger * pageInteger
        List<AssetStigVulnStatus> assetStigVulnStatusValues = AssetStigVulnStatus.findAllWhere (status: "Open")
        if (assetStigVulnStatusValues) {
            List<MitigationStig> mitigationStigs = MitigationStig.list()
            List<CustomStigMit> customStigMits = CustomStigMit.list()
            ArrayList asvsFiltered = asvsFilterService.filterModel(assetStigVulnStatusValues, filterModelEntries, mitigationStigs, customStigMits)
            int asvsCount = asvsFiltered.size()
            int indexStop
            List asvsSorted1
            if (asvsCount) {
                if (asvsCount == 1) {
                    asvsSorted1 = asvsFiltered
                } else if (indexStart + pageSizeInteger <= asvsCount) {
                    indexStop = indexStart + pageSizeInteger - 1
                    List<AssetStigVulnStatus> asvsSorted = asvsSortService.sortModel(asvsFiltered, sortModelEntry) as List
                    asvsSorted1 = asvsSorted[indexStart..indexStop]
                } else {
                    indexStop = asvsCount - 1
                    List<AssetStigVulnStatus> asvsSorted = asvsSortService.sortModel(asvsFiltered, sortModelEntry) as List
                    asvsSorted1 = asvsSorted[indexStart..indexStop]
                }

                asvsSorted1.each { assetStigVulnStatusValue ->
                    // Building map in a single step, If the value is null it will not be added to the map
                    def vulnMap = [id          : assetStigVulnStatusValue.id, asset: assetStigVulnStatusValue.asset.name, stigVulnTitle: assetStigVulnStatusValue.stigVulnerability.ruleTitle,
                                   ipAddress   : assetStigVulnStatusValue.asset.ipAddress, ruleTitle: assetStigVulnStatusValue.stigVulnerability.ruleTitle, vulnNum: assetStigVulnStatusValue.stigVulnerability.vulnNum,
                                   severity    : assetStigVulnStatusValue.stigVulnerability.severity, firstSeen: assetStigVulnStatusValue.firstSeen, vulnDiscuss: assetStigVulnStatusValue.stigVulnerability.vulnDiscuss,
                                   checkContent: assetStigVulnStatusValue.stigVulnerability.checkContent, comment: assetStigVulnStatusValue.stigVulnerability.comment, crit: assetStigVulnStatusValue.asset.crit,
                                   title       : assetStigVulnStatusValue.stigAsset.stig.title, aor: assetStigVulnStatusValue.asset.aor.name, poc: assetStigVulnStatusValue.asset.poc.name]

                    MitigationStig mit = findStigMit(mitigationStigs, assetStigVulnStatusValue)
                    vulnMap += mit ? [mit: true, mitType: mit.mitType, mitId: mit.id, mitStatus: mit.status, mitApproved: mit.approved] : [mit: false, mitType: "NA", mitId: "NA", mitStatus: "NA", mitApproved: false]

                    CustomStigMit customMit = findCustomStigMit(customStigMits, assetStigVulnStatusValue)
                    vulnMap += customMit ? [customMit: true, customMitType: customMit.mitType, customMitId: customMit.id, customMitStatus: customMit.status, customMitApproved: customMit.approved] : [customMit: false, customMitType: "NA", customMitId: "NA", customMitStatus: "NA", customMitApproved: false]
                    vulnTotal << vulnMap
                }
                def vulnTotal1 = ["vulnTotal": vulnTotal]
                def rowCount = ["rowCount": asvsCount]
                def vulnTotal2 = vulnTotal1 + rowCount
                return vulnTotal2
            }
        } else {
            return "None"
        }
    }

    @ReadOnly
    def findCustomStigMit(def customStigMits, def assetStigVulnStatus) {
        for (customStigMit in customStigMits) {
            if (customStigMit.assetStigVulnStatus == assetStigVulnStatus) {
                return customStigMit
            }
        }
        return null
    }

    @ReadOnly
    def findStigMit(def mitigationStigs, def assetStigVulnStatus) {
        for (mitigationStig in mitigationStigs){
            if (mitigationStig.aor == assetStigVulnStatus.asset.aor) {
                if (mitigationStig.stigVulnerability == assetStigVulnStatus.stigVulnerability) {
                    return mitigationStig
                }
            }
        }
        return null
    }

    @ReadOnly
    def getAssetStigVulnStatus(String assetStigVulnStatusId) {
        Long assetStigVulnStatusIdLong = Long.valueOf(assetStigVulnStatusId)
        AssetStigVulnStatus assetStigVulnStatus = AssetStigVulnStatus.findWhere(id: assetStigVulnStatusIdLong)

        return [
                "id": assetStigVulnStatus.id,
                "vulnNum": assetStigVulnStatus.stigVulnerability.vulnNum,
                "ruleTitle": assetStigVulnStatus.stigVulnerability.ruleTitle,
                "aor": assetStigVulnStatus.asset.aor.name,
                "poc": assetStigVulnStatus.asset.poc.name,
                "comment": assetStigVulnStatus.comment
        ]
    }

    //Change STIG Vulnerabilility "Reviewed" and CompStigStatus "Complete" fields to false
    def setAsvsFalse () {
        try {
            List<AssetStigVulnStatus> assetStigVulnStatuses = AssetStigVulnStatus.list()
            if(assetStigVulnStatuses) {
                assetStigVulnStatuses.each { assetStigVulnStatus ->
                    assetStigVulnStatus.reviewed = false
                    assetStigVulnStatus.save()
                }
            } else {
                log.warn ( "No AssetStigVulnStatus instances were found.")
            }
        } catch(e) {
            log.error ( "Failed to update AssetStigVulnStatuses: ${e.message}")
        }

        try {
            List<StigAsset> stigAssets = StigAsset.list()
            if (stigAssets) {
                stigAssets.each {stigAsset ->
                    stigAsset.complete = false
                    stigAsset.save()
                }
            }
            else {
                log.warn ("No Stig Asset instances were found.")
            }
        } catch(e1) {
            log.error "Failed to update AssetStigVulnStatuses: ${e1.message}"
        }
    }

    //updates Asset Stig Vuln Status when uploading SCAP file
    def importScap(byte[] fileData, String stigAsset) {
        Long stigAssetLong = Long.valueOf(stigAsset)
        StigAsset stigAssetObj = StigAsset.findWhere(id: stigAssetLong)
        Asset asset = stigAssetObj.asset
        Stig stig = stigAssetObj.stig
        GPathResult checklist = new XmlSlurper().parseText(new String(fileData))
        def vulns = checklist.STIGS.iSTIG.VULN
        def stigData = checklist.STIGS.iSTIG.STIG_INFO.SI_DATA
        def ipAddress = checklist.ASSET.HOST_IP.text()
        AssetStigVulnStatus assetStigVulnStatus
        if (ipAddress == asset.ipAddress) {
                String stigId = stigData.find { it.SID_NAME.text() == "stigid" }?.SID_DATA.text() as String
            if (stigId) {
                if (stigId == stig.tenable) {
                    vulns.each { vuln ->
                        String vulnNum = vuln.STIG_DATA.find { it.VULN_ATTRIBUTE.text() == "Vuln_Num" }?.ATTRIBUTE_DATA.text() as String
                        if (vulnNum) {
                            StigVulnerability stigVulnerability = StigVulnerability.findWhere(stig: stig, vulnNum: vulnNum)
                            assetStigVulnStatus = AssetStigVulnStatus.findWhere(stigVulnerability: stigVulnerability, stigAsset: stigAssetObj)

                            if (assetStigVulnStatus) {
                                String status = vuln.STATUS.text()
                                assetStigVulnStatus.status = status
                                if (status == "NotAFinding") {
                                    assetStigVulnStatus.comment = "SCAP Review uploaded ${new Date()} Passed"
                                } else if (status == "Open") {
                                    assetStigVulnStatus.comment = "SCAP Review uploaded ${new Date()} Failed"
                                }
                                assetStigVulnStatus.save()
                            }
                        }
                    }
                }
            }
        }
    }

    def getStigVulnDetail (def vulnDetailId){
        String vulnDetailIdString = vulnDetailId.toString()
        Long vulnDetailIdLong = Long.valueOf(vulnDetailIdString)
        AssetStigVulnStatus assetStigVulnStatus = AssetStigVulnStatus.findWhere(id: vulnDetailIdLong)
        Map<String, Object> stigVulnerabilityMap = [
                "ruleTitle"   : assetStigVulnStatus.stigVulnerability.ruleTitle,
                "vulnNum"     : assetStigVulnStatus.stigVulnerability.vulnNum,
                "severity"    : assetStigVulnStatus.stigVulnerability.severity,
                "vulnDiscuss" : assetStigVulnStatus.stigVulnerability.vulnDiscuss,
                "checkContent": assetStigVulnStatus.stigVulnerability.checkContent,
                "fixText"     : assetStigVulnStatus.stigVulnerability.fixText,
                "asset"       : assetStigVulnStatus.asset.name
        ]
        return stigVulnerabilityMap
    }
}