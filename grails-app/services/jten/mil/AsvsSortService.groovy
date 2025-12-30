package jten.mil

import grails.gorm.transactions.ReadOnly
import groovy.json.JsonSlurper

@ReadOnly
class AsvsSortService {

    def sortModel(def asvs, def sortModel) {
        JsonSlurper jsonSlurper = new JsonSlurper()
        def sortMod = jsonSlurper.parseText(sortModel)
        def sortField1 = sortMod.field[0]
        def sortSort1 = sortMod.sort[0]

        def sortingExpressionMap = [
                "firstSeen"    : { it.firstSeen },
                "vulnNum"      : { it.stigVulnerability.vulnNum.toString() },
                "stigVulnTitle": { it.stigVulnerability.ruleTitle.toString() },
                "title"        : { it.stigVulnerability.stig.title.toString() },
                "severity"     : { it.stigVulnerability.severity.toString() },
                "asset"        : { it.asset.name.toString() },
                "ipAddress"    : { it.asset.ipAddress.toString() },
                "aor"          : { it.asset.aor.name.toString() },
                "poc"          : { it.asset.poc.name.toString() }
        ]

        if (sortSort1 && sortingExpressionMap.containsKey(sortField1)) {
            def sortingExpression = sortingExpressionMap[sortField1]
            return sortSort1 == "desc" ? asvs.sort(sortingExpression) : asvs.sort(!sortingExpression)
        } else {
            return asvs
        }
    }
}