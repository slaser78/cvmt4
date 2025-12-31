package jten.mil

import grails.gorm.transactions.ReadOnly
import grails.gorm.transactions.Transactional
import java.text.SimpleDateFormat

@ReadOnly
class Mitigation2Service {

    //get one patch mitigation's fields
    def getPatchMit(String vulnDetailId) {
        Long vulnDetailIdLong = Long.valueOf(vulnDetailId)
        VulnerabilityDetail vulnerabilityDetail = VulnerabilityDetail.findWhere(id: vulnDetailIdLong)
        Mitigation mitValue = Mitigation.findWhere(vulnerability: vulnerabilityDetail.vulnerability, aor: vulnerabilityDetail.asset.aor)
        Map completeDateMap = ["completeDate": mitValue.completeDate]
        Map vulnNameMap = ["vulnName": mitValue.vulnerability.name]
        Map aorMap = ["aor": mitValue.aor.name]
        Map pocMap = ["poc": mitValue.poc.name]
        Map mitTypeMap = ["mitType": mitValue.mitType]
        Map submitCommentMap = ["submitComment": mitValue.submitComment]
        Map mitCommentMap = ["mitComment": mitValue.mitComment]
        Map cyberCommentMap = ["cyberComment": mitValue.cyberComment]
        Map milestoneMap =  ["milestone": mitValue.milestone]
        Map milestoneChangeMap = ["milestoneChange": mitValue.milestoneChange]
        Map resourcesRequiredMap = ["resourcesRequired": mitValue.resourcesRequired]
        Map statusMap = ["status": mitValue.status]
        Map pluginMap = ["plugin": mitValue.vulnerability.plugin]
        def mit1 = completeDateMap + vulnNameMap + aorMap + pocMap + mitTypeMap +
                submitCommentMap + cyberCommentMap + mitCommentMap + milestoneMap + milestoneChangeMap +
                resourcesRequiredMap + statusMap + pluginMap
        return mit1
    }

    def getPatchMit1(String patchMitId) {
        Long patchMitIdLong = Long.valueOf(patchMitId)
        Mitigation mitValue = Mitigation.findWhere(id: patchMitIdLong)
        Map completeDateMap = ["completeDate": mitValue.completeDate]
        Map vulnNameMap = ["vulnName": mitValue.vulnerability.name]
        Map aorMap = ["aor": mitValue.aor.name]
        Map pocMap = ["poc": mitValue.poc.name]
        Map mitTypeMap = ["mitType": mitValue.mitType]
        Map submitCommentMap = ["submitComment": mitValue.submitComment]
        Map mitCommentMap = ["mitComment": mitValue.mitComment]
        Map cyberCommentMap = ["cyberComment": mitValue.cyberComment]
        Map milestoneMap =  ["milestone": mitValue.milestone]
        Map milestoneChangeMap = ["milestoneChange": mitValue.milestoneChange]
        Map resourcesRequiredMap = ["resourcesRequired": mitValue.resourcesRequired]
        Map statusMap = ["status": mitValue.status]
        Map pluginMap = ["plugin": mitValue.vulnerability.plugin]
        Map approvedMap = ["approved": mitValue.approved]
        def mit1 = completeDateMap + vulnNameMap + aorMap + pocMap + mitTypeMap +
                submitCommentMap + cyberCommentMap + mitCommentMap + milestoneMap + milestoneChangeMap +
                resourcesRequiredMap + statusMap + pluginMap + approvedMap
        return mit1
    }

    //get all patch mitigations
    def getPatchMits() {
        List <Mitigation> mitValues = Mitigation.list()
        ArrayList mitTotal = []
        for (mitValue in mitValues) {
            Map idMap = ["id": mitValue.id]
            Map createDateMap = ["createDate": mitValue.createDate]
            Map vulnerabilityMap = ["vulnerability": mitValue.vulnerability.name]
            Map vulnerabilityPluginMap = ["plugin": mitValue.vulnerability.plugin]
            Map completeDateMap = ["completeDate": mitValue.completeDate]
            Map statusMap = ["status": mitValue.status]
            Map mitTypeMap = ["mitType": mitValue.mitType]
            Map approvedMap = ["approved": mitValue.approved]
            Map cyberCommentMap = ["cyberComment": mitValue.cyberComment]
            Map mitCommentMap = ["mitComment": mitValue.mitComment]
            Map submitCommentMap = ["submitComment": mitValue.submitComment]
            Map milestoneMap = ["milestone": mitValue.milestone]
            Map milestoneChangeMap = ["milestoneChange": mitValue.milestoneChange]
            Map resourcesRequiredMap = ["resourcesRequired": mitValue.resourcesRequired]
            Map pocMap = ["poc": mitValue.poc.name]
            Map aorMap = ["aor": mitValue.aor.name]

            mitTotal += idMap + completeDateMap + vulnerabilityMap + vulnerabilityPluginMap + createDateMap + statusMap + mitTypeMap +
                    approvedMap + mitCommentMap + submitCommentMap + milestoneMap + milestoneChangeMap +
                    resourcesRequiredMap + pocMap + aorMap + cyberCommentMap
        }
        return mitTotal
    }

    //get all custom patch mitigations
    def getCustomPatchMits() {
        List <CustomPatchMit> mitValues = CustomPatchMit.list()
        ArrayList mitTotal = []
        for (mitValue in mitValues) {
            Map idMap = ["id": mitValue.id]
            Map createDateMap = ["createDate": mitValue.createDate]
            Map vulnerabilityMap = ["vulnerability": mitValue.vulnerabilityDetail.vulnerability.name]
            Map vulnerabilityPluginMap = ["plugin": mitValue.vulnerabilityDetail.vulnerability.plugin]
            Map assetNameMap = ["assetName": mitValue.vulnerabilityDetail.asset.name]
            Map ipAddressMap = ["ipAddress": mitValue.vulnerabilityDetail.asset.ipAddress]
            Map completeDateMap = ["completeDate": mitValue.completeDate]
            Map statusMap = ["status": mitValue.status]
            Map mitTypeMap = ["mitType": mitValue.mitType]
            Map approvedMap = ["approved": mitValue.approved]
            Map cyberCommentMap = ["cyberComment": mitValue.cyberComment]
            Map mitCommentMap = ["mitComment": mitValue.mitComment]
            Map submitCommentMap = ["submitComment": mitValue.submitComment]
            Map milestoneMap = ["milestone": mitValue.milestone]
            Map milestoneChangeMap = ["milestoneChange": mitValue.milestoneChange]
            Map resourcesRequiredMap = ["resourcesRequired": mitValue.resourcesRequired]
            Map pocMap = ["poc": mitValue.vulnerabilityDetail.asset.poc.name]
            Map aorMap = ["aor": mitValue.vulnerabilityDetail.asset.aor.name]

            mitTotal += idMap + completeDateMap + vulnerabilityMap + vulnerabilityPluginMap + createDateMap + statusMap + mitTypeMap +
                    approvedMap + mitCommentMap + submitCommentMap + milestoneMap + milestoneChangeMap +
                    resourcesRequiredMap + pocMap + aorMap + cyberCommentMap + assetNameMap + ipAddressMap
        }
        return mitTotal
    }

    def getCustomPatchMit(String vulnDetailId) {
        Long vulnDetailIdLong = Long.valueOf(vulnDetailId)
        VulnerabilityDetail vulnDetail = VulnerabilityDetail.findWhere(id: vulnDetailIdLong)
        CustomPatchMit customPatchMit = vulnDetail.customPatchMit
        if (customPatchMit) {
            Map idMap = ["id": customPatchMit.id]
            Map pluginMap = ["plugin": customPatchMit.vulnerabilityDetail.vulnerability.plugin]
            Map aorMap = ["aor": customPatchMit.vulnerabilityDetail.asset.aor.name]
            Map pocMap = ["poc": customPatchMit.vulnerabilityDetail.asset.poc.name]
            Map submitCommentMap = ["submitCommentMap": customPatchMit.submitComment]
            Map mitCommentMap = ["mitComment": customPatchMit.mitComment]
            Map completeDateMap = ["completeDate": customPatchMit.completeDate]
            Map mitStatusMap = ["status": customPatchMit.status]
            Map mitTypeMap = ["mitType": customPatchMit.mitType]
            Map vulnNameMap = ["vulnName": customPatchMit.vulnerabilityDetail.vulnerability.name]
            Map vulnDetailIdMap = ["vulnDetailId": customPatchMit.vulnerabilityDetail.id]
            Map milestoneMap = ["milestone": customPatchMit.milestone]
            Map milestoneChangeMap = ["milestoneChange": customPatchMit.milestoneChange]
            Map resourcesRequiredMap = ["resourcesRequired": customPatchMit.resourcesRequired]
            def result = (pluginMap + aorMap + pocMap + submitCommentMap + mitCommentMap + completeDateMap +
                    mitTypeMap + vulnNameMap + milestoneMap + milestoneChangeMap + vulnDetailIdMap +
                    resourcesRequiredMap + idMap + mitStatusMap)
            return result
        }
        return null
    }

    def getCustomPatchMit1(String customPatchMitId){
        Long idLong = Long.valueOf(customPatchMitId)
        CustomPatchMit customPatchMit = CustomPatchMit.findWhere(id: idLong)
        Map idMap = ["id": customPatchMit.id]
        Map pluginMap = ["vulnNum" : customPatchMit.vulnerabilityDetail.vulnerability.plugin]
        Map aorMap = ["aor": customPatchMit.vulnerabilityDetail.asset.aor.name]
        Map pocMap = ["poc": customPatchMit.vulnerabilityDetail.asset.poc.name]
        Map submitCommentMap = ["submitComment": customPatchMit.submitComment]
        Map mitCommentMap = ["mitComment": customPatchMit.mitComment]
        Map completeDateMap = ["completeDate": customPatchMit.completeDate]
        Map mitStatusMap = ["status": customPatchMit.status]
        Map mitTypeMap = ["mitType": customPatchMit.mitType]
        Map vulnNameMap = ["vulnName": customPatchMit.vulnerabilityDetail.vulnerability.name]
        Map vulnDetailIdMap = ["vulnDetailId": customPatchMit.vulnerabilityDetail.id]
        Map milestoneMap = ["milestone": customPatchMit.milestone]
        Map milestoneChangeMap = ["milestoneChange": customPatchMit.milestoneChange]
        Map resourcesRequiredMap = ["resourcesRequired": customPatchMit.resourcesRequired]
        Map cyberCommentMap = ["cyberComment": customPatchMit.cyberComment]
        Map approvedMap = ["approved": customPatchMit.approved]
        return (pluginMap + aorMap + pocMap + submitCommentMap + mitCommentMap + completeDateMap +
                mitTypeMap + vulnNameMap + milestoneMap + milestoneChangeMap + vulnDetailIdMap +
                resourcesRequiredMap + idMap + mitStatusMap + cyberCommentMap + approvedMap)
    }

    @Transactional
    def setCustomPatchMit(def valuesReturned){
        String valuesReturnedString = valuesReturned.id.toString()
        Long idLong = Long.valueOf(valuesReturnedString)
        CustomPatchMit customPatchMit = CustomPatchMit.findWhere(id: idLong)
        String pattern = "MM/dd/yyyy"
        String completeDateString = valuesReturned.completeDate.toString()
        Date completeDate = new SimpleDateFormat(pattern).parse(completeDateString)
        customPatchMit.completeDate = completeDate
        if (valuesReturned.milestone) {
            customPatchMit.milestone = valuesReturned.milestone
        }
        if (valuesReturned.milestoneChange) {
            customPatchMit.milestoneChange = valuesReturned.milestoneChange
        }
        if (valuesReturned.resourcesRequired) {
            customPatchMit.resourcesRequired = valuesReturned.resourcesRequired
        }
        if (valuesReturned.mitComment) {
            customPatchMit.mitComment = valuesReturned.mitComment
        }
        if (valuesReturned.submitComment) {
            customPatchMit.submitComment = valuesReturned.submitComment
        }
        customPatchMit.save()
        log.warn ("Updated Custom Patch Mitigation")
    }

    //get on assetStigVulnStatus entry's mitigation details
    def getStigMit(String assetStigVulnStatusId) {
        Long assetStigVulnStatusLong = Long.valueOf(assetStigVulnStatusId)
        AssetStigVulnStatus assetStigVulnStatus = AssetStigVulnStatus.findWhere(id: assetStigVulnStatusLong)
        MitigationStig mitigationStig = MitigationStig.findWhere(stigVulnerability: assetStigVulnStatus.stigVulnerability, aor: assetStigVulnStatus.asset.aor)
        LinkedHashMap<String, Date> completeDateMap = ['completeDate': mitigationStig.completeDate]
        LinkedHashMap<String, String> vulnNumMap = ["vulnNum": mitigationStig.stigVulnerability.vulnNum]
        LinkedHashMap<String, String> ruleTitleMap = ["ruleTitle": mitigationStig.stigVulnerability.ruleTitle]
        LinkedHashMap<String, String> aorMap = ["aor": mitigationStig.aor.name]
        LinkedHashMap<String, String> pocMap = ["poc": mitigationStig.poc.name]
        LinkedHashMap<String, String> mitTypeMap = ["mitType": mitigationStig.mitType]
        LinkedHashMap<String, String> submitCommentMap = ["submitComment": mitigationStig.submitComment]
        LinkedHashMap<String, String> mitCommentMap = ["mitComment": mitigationStig.mitComment]
        LinkedHashMap<String, String> cyberCommentMap = ["cyberComment": mitigationStig.cyberComment]
        LinkedHashMap<String, String> milestoneMap = ["milestone": mitigationStig.milestone]
        LinkedHashMap<String, String> milestoneChangeMap = ["milestoneChange": mitigationStig.milestoneChange]
        LinkedHashMap<String, String> resourceMap = ["resourcesRequired": mitigationStig.resourcesRequired]
        LinkedHashMap<String, String> statusMap = ["status": mitigationStig.status]
        def mit1 = completeDateMap + vulnNumMap + aorMap + pocMap + mitTypeMap +
                submitCommentMap + cyberCommentMap + mitCommentMap + milestoneMap + milestoneChangeMap + ruleTitleMap +
                resourceMap + statusMap
        return mit1
    }

    //get all mitigation STIGs
    def getStigMits() {
        ArrayList mitValues = MitigationStig.list()
        ArrayList mitTotal = []
        if (mitValues) {
            for (mitValue in mitValues) {
                Map idMap = ["id": mitValue.id]
                Map createDateMap = ["createDate": mitValue.createDate]
                Map mitNameMap = ["mitName": mitValue.name]
                Map stigMap = ["stig": mitValue.stigVulnerability.stig.title]
                Map vulnNumMap = ["vulnNum": mitValue.stigVulnerability.vulnNum]
                Map ruleTitleMap = ["ruleTitle": mitValue.stigVulnerability.ruleTitle]
                Map completeDateMap = ["completeDate": mitValue.completeDate.toString()]
                Map statusMap = ["status": mitValue.status]
                Map mitTypeMap = ["mitType": mitValue.mitType]
                Map approvedMap = ["approved": mitValue.approved]
                Map cyberCommentMap = ["cyberComment": mitValue.cyberComment]
                Map mitCommentMap = ["mitComment": mitValue.mitComment]
                Map submitCommentMap = ["submitComment": mitValue.submitComment]
                Map milestoneMap = ["milestone": mitValue.milestone]
                Map milestoneChangeMap = ["milestoneChange": mitValue.milestoneChange]
                Map resourceMap = ["resourcesRequired": mitValue.resourcesRequired]
                Map pocMap = ["poc": mitValue.poc.name]
                Map aorMap = ["aor": mitValue.aor.name]
                mitTotal += idMap + createDateMap + mitNameMap + vulnNumMap + ruleTitleMap + completeDateMap + statusMap + mitTypeMap +
                        approvedMap + mitCommentMap + submitCommentMap + milestoneMap + milestoneChangeMap +
                        resourceMap + pocMap + aorMap + cyberCommentMap + stigMap
            }
            return mitTotal
        } else {
            return "None"
        }
    }

    //get all mitigation STIGs
    def getCustomStigMits() {
        ArrayList mitValues = CustomStigMit.list()
        ArrayList mitTotal = []
        if (mitValues) {
            for (mitValue in mitValues) {
                Map idMap = ["id": mitValue.id]
                Map createDateMap = ["createDate": mitValue.createDate]
                Map mitNameMap = ["mitName": mitValue.name]
                Map vulnNumMap = ["vulnNum": mitValue.assetStigVulnStatus.stigVulnerability.vulnNum]
                Map ruleTitleMap = ["ruleTitle": mitValue.assetStigVulnStatus.stigVulnerability.ruleTitle]
                Map assetNameMap = ["assetName": mitValue.assetStigVulnStatus.asset.name]
                Map ipAddressMap = ["ipAddress": mitValue.assetStigVulnStatus.asset.ipAddress]
                Map completeDateMap = ["completeDate": mitValue.completeDate.toString()]
                Map stigMap = ["stig": mitValue.assetStigVulnStatus.stigVulnerability.stig.title]
                Map statusMap = ["status": mitValue.status]
                Map mitTypeMap = ["mitType": mitValue.mitType]
                Map approvedMap = ["approved": mitValue.approved]
                Map cyberCommentMap = ["cyberComment": mitValue.cyberComment]
                Map mitCommentMap = ["mitComment": mitValue.mitComment]
                Map submitCommentMap = ["submitComment": mitValue.submitComment]
                Map milestoneMap = ["milestone": mitValue.milestone]
                Map milestoneChangeMap = ["milestoneChange": mitValue.milestoneChange]
                Map resourceMap = ["resourcesRequired": mitValue.resourcesRequired]
                Map pocMap = ["poc": mitValue.assetStigVulnStatus.asset.poc.name]
                Map aorMap = ["aor": mitValue.assetStigVulnStatus.asset.aor.name]
                mitTotal += idMap + createDateMap + mitNameMap + vulnNumMap + ruleTitleMap + completeDateMap + statusMap + mitTypeMap +
                        approvedMap + mitCommentMap + submitCommentMap + milestoneMap + milestoneChangeMap +
                        resourceMap + pocMap + aorMap + cyberCommentMap + assetNameMap + ipAddressMap + stigMap
            }
            return mitTotal
        }
        else {
            return "None"
        }
    }

    def getCustomStigMit(String id){
        Long idLong = Long.valueOf(id)
        AssetStigVulnStatus assetStigVulnStatus = AssetStigVulnStatus.findWhere(id: idLong)
        CustomStigMit customStigMit = CustomStigMit.findWhere(assetStigVulnStatus: assetStigVulnStatus)
        Map idMap = ["id": customStigMit.id]
        Map vulnNumMap = ["vulnNum" : assetStigVulnStatus.stigVulnerability.vulnNum]
        Map aorMap = ["aor": assetStigVulnStatus.asset.aor.name]
        Map pocMap = ["poc": assetStigVulnStatus.asset.poc.name]
        Map submitCommentMap = ["submitCommentMap": customStigMit.submitComment]
        Map mitCommentMap = ["mitComment": customStigMit.mitComment]
        Map completeDateMap = ["completeDate": customStigMit.completeDate]
        Map mitTypeMap = ["mitType": customStigMit.mitType]
        Map ruleTitleMap = ["ruleTitle": assetStigVulnStatus.stigVulnerability.ruleTitle]
        Map assetStigVulnStatusIdMap = ["assetStigVulnStatusId": assetStigVulnStatus.id]
        Map milestoneMap = ["milestone": customStigMit.milestone]
        Map milestoneChangeMap = ["milestoneChange": customStigMit.milestoneChange]
        Map resourcesRequiredMap = ["resourcesRequired": customStigMit.resourcesRequired]
        Map cyberCommentMap = ["cyberComment": customStigMit.cyberComment]
        Map statusMap = ["status": customStigMit.status]
        return (vulnNumMap + aorMap + pocMap + submitCommentMap + mitCommentMap + completeDateMap +
                mitTypeMap + ruleTitleMap + assetStigVulnStatusIdMap + milestoneMap + milestoneChangeMap +
                resourcesRequiredMap + idMap + cyberCommentMap + statusMap)
    }

    @Transactional
    def setCustomStigMit(def valuesReturned) {
        String assetStigVulnStatusIdString =  valuesReturned.assetStigVulnStatus.id.toString()
        Long idLong = Long.valueOf(assetStigVulnStatusIdString)
        AssetStigVulnStatus assetStigVulnStatus = AssetStigVulnStatus.findWhere(id: idLong)
        CustomStigMit customStigMit = CustomStigMit.findWhere(assetStigVulnStatus: assetStigVulnStatus)
        String pattern = "MM/dd/yyyy"
        String completeDateString = valuesReturned.completeDate.toString()
        Date completeDate = new SimpleDateFormat(pattern).parse(completeDateString)
        customStigMit.completeDate = completeDate
        if (valuesReturned.milestone) {
            customStigMit.milestone = valuesReturned.milestone
        }
        if (valuesReturned.milestoneChange) {
            customStigMit.milestoneChange = valuesReturned.milestoneChange
        }
        if (valuesReturned.resourcesRequired) {
            customStigMit.resourcesRequired = valuesReturned.resourcesRequired
        }
        if (valuesReturned.mitComment) {
            customStigMit.mitComment = valuesReturned.mitComment
        }
        if (valuesReturned.submitComment) {
            customStigMit.submitComment = valuesReturned.submitComment
        }
        log.warn ("Updated Custom STIG Mitigation")
        customStigMit.save()
    }

    //Deletes empty patch mitigations
    @Transactional
    def delMit() {
        //retrieve patch mitigation list
        List <Mitigation> mits = Mitigation.list()
        //retrieve patch vulnerability detail list
        List <VulnerabilityDetail> vulnDetails = VulnerabilityDetail.list()
        //if there are patch mitigations
        if (mits) {
            //for each patch mitigation
            for (mit in mits) {
                Boolean match1 = false
                //if there are vulnDetails entries
                if (vulnDetails) {
                    for (vulnDetail in vulnDetails) {
                        if (!match1) {
                            //check each vulnDetail entry for AOR match with mitigation
                            if (vulnDetail.asset.aor == mit.aor) {
                                //check each vulnDetail entry for vulnerability match with mitigation
                                if (vulnDetail.vulnerability == mit.vulnerability) {
                                    //if match exists set match1 to true
                                    match1 = true
                                }
                            }
                        }
                    }
                    //if no matches are found, delete the mitigation
                    if (match1 == false) {
                        log.warn("Delete Mit with vulnerability: ${mit.vulnerability.plugin} and AOR: ${mit.aor.name}")
                        mit.delete()
                    }
                }
            }
        }
        //delete empty STIG mitigations
        List <MitigationStig> mits1 = MitigationStig.list()
        List <AssetStigVulnStatus> assetStigVulnStatuses = AssetStigVulnStatus.list()
        if (mits1) {
            //if there are STIG mitigations
            for (mit1 in mits1) {
                Boolean match1 = false
                //if there are Asset STIG Vulnerability Status entries
                if (assetStigVulnStatuses) {
                    //check each assetStigVulnStatus entry to determine there are stigVulnerabilities for that AOR's STIG mitigations
                    for (assetStigVulnStatus in assetStigVulnStatuses) {
                        if (!match1) {
                            if (assetStigVulnStatus.asset.aor == mit1.aor) {
                                if (assetStigVulnStatus.stigVulnerability == mit1.stigVulnerability) {
                                    match1 = true
                                }
                            }
                        }
                    }
                    //if no matches are found, delete the mitigation
                    if (match1 == false) {
                        log.warn("Delete Mit with vulnerability: ${mit1.stigVulnerability.vulnNum} and AOR: ${mit1.aor.name}")
                        mit1.delete()
                    }
                }
            }
        }
    }
}