package jten.mil

import grails.gorm.transactions.ReadOnly
import groovy.json.JsonSlurper

@ReadOnly
class AsvsFilterService {

    def filterModel (List<AssetStigVulnStatus> asvs, def filterModel, def mitigationStigs, def customStigMits) {
        JsonSlurper jsonSlurper = new JsonSlurper()
        def filterMod1 = jsonSlurper.parseText(filterModel)
        def filterModItems = filterMod1.items
        def filterModLogicOperator = filterMod1.logicOperator
        def logicOperator = (filterModLogicOperator) ? filterModLogicOperator[0] : null
        if (logicOperator == "and" || !logicOperator) {
            if (filterModItems) {
                int itemsCount = filterModItems.size()
                if (itemsCount == 1) {
                    return (filterFields(filterModItems[0], asvs, mitigationStigs, customStigMits))
                } else {
                    def results = []
                    def results1 = asvs
                    for (int i = 0; i < itemsCount; i++) {
                        results = filterFields(filterModItems[i], results1, mitigationStigs, customStigMits)
                        results1 = results
                    }
                    return results
                }
            } else {
                return asvs
            }
        } else {
            if (filterModItems) {
                int itemsCount = filterModItems.size()
                if (itemsCount == 1) {
                    return (filterFields(filterModItems[0], asvs, mitigationStigs, customStigMits))
                } else {
                    def results = []
                    def results1 = []
                    for (int i = 0; i < itemsCount; i++) {
                        results = filterFields(filterModItems[i], asvs, mitigationStigs, customStigMits)
                        results1 += results
                    }
                    def results2 = results1.unique()
                    return results2
                }
            } else {
                return asvs
            }

        }
    }

    def filterFields( def item, def asvs, def mitigationStigs, def customStigMits) {
        def entries = []
        if (item.value) {
            //POC
            if (item.field == "poc") {
                if (item.operator == "equals") {
                    for (asvsEntry in asvs) {
                        if (asvsEntry.asset.poc.name == item.value) {
                            entries += asvsEntry
                        }
                    }
                } else if (item.operator == "contains") {
                    for (asvsEntry in asvs) {
                        if ((asvsEntry.asset.poc.name).contains(item.value)) {
                            entries += asvsEntry
                        }
                    }
                } else {
                    entries = asvs
                }
            }
            //AOR
            else if (item.field == "aor") {
                if (item.operator == "equals") {
                    for (asvsEntry in asvs) {
                        if (asvsEntry.asset.aor.name == item.value) {
                            entries += asvsEntry
                        }
                    }
                } else if (item.operator == "contains") {
                    for (asvsEntry in asvs) {
                        if ((asvsEntry.asset.aor.name).contains(item.value)) {
                            entries += asvsEntry
                        }
                    }
                } else {
                    entries = asvs
                }
            }
            //Asset STIG Vulnerability Number
            else if (item.field == "vulnNum") {
                if (item.operator == "equals") {
                    for (asvsEntry in asvs) {
                        if (asvsEntry.stigVulnerability.vulnNum == item.value) {
                            entries += asvsEntry
                        }
                    }
                } else if (item.operator == "contains") {
                    for (asvsEntry in asvs) {
                        if ((asvsEntry.stigVulnerability.vulnNum).contains(item.value)) {
                            entries += asvsEntry
                        }
                    }
                } else {
                    entries = asvs
                }
            }
            //Asset STIG Vulnerability Rule Title
            else if (item.field == "stigVulnTitle") {
                if (item.operator == "equals") {
                    for (asvsEntry in asvs) {
                        if (asvsEntry.stigVulnerability.ruleTitle == item.value) {
                            entries += asvsEntry
                        }
                    }
                } else if (item.operator == "contains") {
                    for (asvsEntry in asvs) {
                        if ((asvsEntry.stigVulnerability.ruleTitle).contains(item.value)) {
                            entries += asvsEntry
                        }
                    }
                } else {
                    entries = asvs
                }
            }
            //Asset STIG Vulnerability STIG title
            else if (item.field == "title") {
                if (item.operator == "equals") {
                    for (asvsEntry in asvs) {
                        if (asvsEntry.stigVulnerability.stig.title == item.value) {
                            entries += asvsEntry
                        }
                    }
                } else if (item.operator == "contains") {
                    for (asvsEntry in asvs) {
                        if ((asvsEntry.stigVulnerability.stig.title).contains(item.value)) {
                            entries += asvsEntry
                        }
                    }
                } else {
                    entries = asvs
                }
            }
            //Asset STIG Vulnerability severity
            else if (item.field == "severity") {
                if (item.operator == "equals") {
                    for (asvsEntry in asvs) {
                        if (asvsEntry.stigVulnerability.severity == item.value) {
                            entries += asvsEntry
                        }
                    }
                } else if (item.operator == "contains") {
                    for (asvsEntry in asvs) {
                        if ((asvsEntry.stigVulnerability.severity).contains(item.value)) {
                            entries += asvsEntry
                        }
                    }
                } else {
                    entries = asvs
                }
            }
            //Asset STIG Vulnerability asset's name
            else if (item.field == "asset") {
                if (item.operator == "equals") {
                    for (asvsEntry in asvs) {
                        if (asvsEntry.asset.name == item.value) {
                            entries += asvsEntry
                        }
                    }
                } else if (item.operator == "contains") {
                    for (asvsEntry in asvs) {
                        if ((asvsEntry.asset.name).contains(item.value)) {
                            entries += asvsEntry
                        }
                    }
                } else {
                    entries = asvs
                }
            }
            //Asset STIG Vulnerability asset's ip address
            else if (item.field == "ipAddress") {
                if (item.operator == "equals") {
                    for (asvsEntry in asvs) {
                        if (asvsEntry.asset.ipAddress == item.value) {
                            entries += asvsEntry
                        }
                    }
                } else if (item.operator == "contains") {
                    for (asvsEntry in asvs) {
                        if ((asvsEntry.asset.ipAddress).contains(item.value)) {
                            entries += asvsEntry
                        }
                    }
                } else {
                    entries = asvs
                }
            }
            //Asset STIG Vulnerability's asset critical field
            else if (item.field == "critical") {
                if (item.operator == "equals") {
                    for (asvsEntry in asvs) {
                        if (asvsEntry.asset.critical == item.value) {
                            entries += asvsEntry
                        }
                    }
                } else if (item.operator == "contains") {
                    for (asvsEntry in asvs) {
                        if ((asvsEntry.asset.critical).contains(item.value)) {
                            entries += asvsEntry
                        }
                    }
                } else {
                    entries = asvs
                }
            }
            //Asset STIG Mitigation Type
            else if (item.field == "mitType") {
                if (item.operator == "equals") {
                    for (asvsEntry in asvs) {
                        MitigationStig mitigation = findStigMit(mitigationStigs, asvsEntry)
                        if (mitigation) {
                            if (mitigation.mitType == item.value) {
                                entries += asvsEntry
                            }
                        }
                    }
                } else if (item.operator == "contains") {
                    def noMit = "NA"
                    for (asvsEntry in asvs) {
                        MitigationStig mitigation = findStigMit(mitigationStigs, asvsEntry)
                        if (mitigation) {
                            if (mitigation.mitType.contains(item.value)) {
                                entries += asvsEntry
                            }
                        } else {
                            if (noMit.contains(item.value)) {
                                entries += asvsEntry
                            }
                        }
                    }
                } else {
                    entries = asvs
                }
            }
            //AOR STIG Mitigation exists
            else if (item.field == "mit") {
                for (asvsEntry in asvs) {
                    MitigationStig stigMit = findStigMit(mitigationStigs, asvsEntry)
                    if (stigMit && item.value == "true") {
                        entries += asvsEntry
                    } else if (!stigMit && item.value == "false") {
                        entries += asvsEntry
                    }
                }
            }
            //AOR STIG Mitigation approved
            else if (item.field == "mitApproved") {
                for (asvsEntry in asvs) {
                    MitigationStig stigMit = findStigMit(mitigationStigs, asvsEntry)
                    if (stigMit && item.value == "true") {
                        entries += asvsEntry
                    } else if (!stigMit && item.value == "false") {
                        entries += asvsEntry
                    }
                }
            }
            //Custom Mit Type
            else if (item.field == "customMitType") {
                if (item.operator == "equals") {
                    for (asvsEntry in asvs) {
                        CustomStigMit customStigMit = findCustomStigMit(customStigMits, asvsEntry)
                        if (customStigMit) {
                            if (customStigMit.mitType == item.value) {
                                entries += asvsEntry
                            }
                        }
                    }
                } else if (item.operator == "contains") {
                    for (asvsEntry in asvs) {
                        if (asvsEntry.customStigMit) {
                            CustomStigMit customStigMit = CustomStigMit.findWhere(assetStigVulnStatus: asvsEntry)
                            if (customStigMit.mitType.contains(item.value)) {
                                entries += asvsEntry
                            }
                        } else {
                            entries = asvs
                        }
                    }
                }
            }
            //Custom Mitigation exists
            else if (item.field == "customMit") {
                for (asvsEntry in asvs) {
                    if (asvsEntry.customStigMit && item.value == "true") {
                        entries += asvsEntry
                    } else if (!asvsEntry.customStigMit && item.value == "false") {
                        entries += asvsEntry
                    }
                }
            }
            //Custom Mitigation approved
            else if (item.field == "customMitApproved") {
                for (asvsEntry in asvs) {
                    if (asvsEntry.customStigMit && item.value == "true") {
                        entries += asvsEntry
                    } else if (!asvsEntry.customStigMit && item.value == "false") {
                        entries += asvsEntry
                    }
                }
            }
            //First Seen Date
            else if (item.field == "firstSeen") {
                for (asvsEntry in asvs) {
                    String date1 = asvsEntry.firstSeen.toString()
                    def date1a = formatDateString(date1, "yyyy-MM-dd HH:mm:ss.SSS", "yyyy-MM-dd")
                    def date1b = Date.parse('yyyy-MM-dd', date1a)
                    def date2 = Date.parse("yyyy-MM-dd", item.value)
                    if (item.operator == "is") {
                        if (date1b.equals(date2)) {
                            entries += asvsEntry
                        }
                    } else if (item.operator == "not") {
                        if (!date1b.equals(date2)){
                            entries += asvsEntry
                        }
                    } else if (item.operator == "after") {
                        if (date1b.after(date2)) {
                            entries += asvsEntry
                        }
                    } else if (item.operator == "before") {
                        if (date1b.before(date2)) {
                            entries += asvsEntry
                        }
                    }
                }
                return entries
            }
        } else {
            entries = asvs
        }
        return entries
    }

    @ReadOnly
    def formatDateString(String inputDate, String inputFormat, String outputFormat) {
        Date date = Date.parse(inputFormat, inputDate)
        return date.format(outputFormat)
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
}