package jten.mil

import grails.core.GrailsApplication
import grails.gorm.transactions.Transactional
import groovy.io.FileType
import groovy.json.JsonSlurper
import groovy.xml.MarkupBuilder
import groovy.xml.slurpersupport.GPathResult

import org.apache.hc.client5.http.classic.methods.HttpPost
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder
import org.apache.hc.core5.http.io.entity.StringEntity

import java.nio.file.Files
import java.nio.file.Paths
import java.text.SimpleDateFormat
import groovy.xml.XmlSlurper
import java.util.zip.ZipFile

@Transactional
class Stig2Service {
    GrailsApplication grailsApplication
    def lookupService

    //retrieve STIG vulnerabilities
    def getStigVulnerabilities(String stig) {
        Long stigLong = Long.valueOf(stig)
        def stigValue = Stig.findWhere(id: stigLong)
        def stigVulns = StigVulnerability.findAllWhere(stig: stigValue)
        def stigTotal = []
        for (stigVuln in stigVulns) {
            def stigMap1 = [:]
            def stigMap2 = [:]
            def stigMap3 = [:]
            def stigMap4 = [:]
            def stigMap5 = [:]
            def stigMap6 = [:]
            def stigMap7 = [:]
            def stigMap8 = [:]
            def stigMap9 = [:]
            def stigMap10 = [:]
            def stigMap11 = [:]
            def stigMap12 = [:]
            def stigMap13 = [:]
            def stigMap14 = [:]
            def stigMap15 = [:]
            def stigMap16 = [:]
            stigMap1.put("vulnNum", stigVuln.vulnNum)
            stigMap2.put("ruleTitle", stigVuln.ruleTitle)
            stigMap3.put("severity", stigVuln.severity)
            stigMap4.put("status", stigVuln.status)
            stigMap5.put("responsibility", stigVuln.responsibility)
            stigMap6.put("groupTitle", stigVuln.groupTitle)
            stigMap7.put("ruleId", stigVuln.ruleId)
            stigMap8.put("ruleVer", stigVuln.ruleVer)
            stigMap9.put("stigRef", stigVuln.stigRef)
            stigMap10.put("iaControls", stigVuln.iaControls)
            stigMap11.put("classification", stigVuln.class1)
            stigMap12.put("vulnDiscuss", stigVuln.vulnDiscuss)
            stigMap13.put("checkContent", stigVuln.checkContent)
            stigMap14.put("fixText", stigVuln.fixText)
            stigMap15.put("comment", stigVuln.comment)
            stigMap16.put("id", stigVuln.id)
            stigTotal.add(stigMap1 + stigMap2 + stigMap3 + stigMap4 + stigMap5 +
                    stigMap6 + stigMap7 + stigMap8 + stigMap9 + stigMap10 +
                    stigMap11 + stigMap12 + stigMap13 + stigMap14 + stigMap15 + stigMap16)
        }
        def stigTotal1 = ["stigTotal": stigTotal]
        def stig1 = ["stig": stigVulns[0].stig.title]
        return stigTotal1 + stig1
    }

    //exports one asset's STIGs to a ckl file
    def exportAssetStig(Asset asset) {
        def xmlWriter = new StringWriter()
        def xmlMarkup = new MarkupBuilder(xmlWriter)
        def xmlHeaderString = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        def xmlHeaderString2 = "<!--DISA STIG Viewer :: 2.9-->"
        xmlMarkup.CHECKLIST {
            ASSET {
                ROLE("${asset.role}")
                ASSET_TYPE("${asset.assetType}")
                HOST_NAME("${asset.name}")
                HOST_IP("${asset.ipAddress}")
                if (asset.macAddress) {
                    HOST_MAC("${asset.macAddress}")
                } else {
                    HOST_MAC()
                }
                HOST_FQDN("${asset.name}")
                TECH_AREA("${asset.techArea}")
                TARGET_KEY()
                WEB_OR_DATABASE("${asset.webOrDatabase}")
                if (asset.webOrDatabaseSite) {
                    WEB_DB_SITE("${asset.webOrDatabaseSite}")
                } else {
                    WEB_DB_SITE()
                }
                if (asset.webOrDatabaseInstance) {
                    WEB_DB_INSTANCE("${asset.webOrDatabaseInstance}")
                } else {
                    WEB_DB_INSTANCE()
                }
            }
            if (asset.stigAsset) {
                STIGS {
                    for (entry in asset.stigAsset) {
                        iSTIG {
                            STIG_INFO {
                                SI_DATA {
                                    SID_NAME("version")
                                    SID_DATA("${entry.stig.version1}")
                                }
                                SI_DATA {
                                    SID_NAME("classification")
                                    SID_DATA("${entry.stig.classification}")
                                }
                                if (entry.stig.customName) {
                                    SI_DATA {
                                        SID_NAME("customname")
                                        SID_DATA("${entry.stig.customName}")
                                    }
                                } else {
                                    SI_DATA {
                                        SID_NAME("customname")
                                        SID_DATA()
                                    }
                                }
                                SI_DATA {
                                    SID_NAME("stigid")
                                    SID_DATA("${entry.stig.stigId}")
                                }
                                SI_DATA {
                                    SID_NAME("description")
                                    SID_DATA("${entry.stig.description}")
                                }
                                SI_DATA {
                                    SID_NAME("filename")
                                    SID_DATA("${entry.stig.fileName}")
                                }
                                if (entry.stig.releaseInfo) {
                                    SI_DATA {
                                        SID_NAME("releaseinfo")
                                        SID_DATA("${entry.stig.releaseInfo}")
                                    }
                                } else {
                                    SI_DATA {
                                        SID_NAME("releaseinfo")
                                        SID_DATA()
                                    }
                                }
                                SI_DATA {
                                    SID_NAME("title")
                                    SID_DATA("${entry.stig.title}")
                                }
                                SI_DATA {
                                    SID_NAME("uuid")
                                    SID_DATA("${entry.stig.uuid}")
                                }
                                SI_DATA {
                                    SID_NAME("notice")
                                    SID_DATA("${entry.stig.notice}")
                                }
                                if (entry.stig.source) {
                                    SI_DATA {
                                        SID_NAME("source")
                                        SID_DATA("${entry.stig.source}")
                                    }
                                } else {
                                    SI_DATA {
                                        SID_NAME("source")
                                        SID_DATA()
                                    }
                                }
                            }
                            def stigVuln = StigVulnerability.findAllWhere(stig: entry.stig)
                            for (entry1 in stigVuln) {
                                VULN {
                                    STIG_DATA {
                                        VULN_ATTRIBUTE("Vuln_Num")
                                        ATTRIBUTE_DATA("${entry1.vulnNum}")
                                    }
                                    STIG_DATA {
                                        VULN_ATTRIBUTE("Severity")
                                        ATTRIBUTE_DATA("${entry1.severity}")
                                    }
                                    STIG_DATA {
                                        VULN_ATTRIBUTE("Group_Title")
                                        ATTRIBUTE_DATA("${entry1.groupTitle}")
                                    }
                                    STIG_DATA {
                                        VULN_ATTRIBUTE("Rule_ID")
                                        ATTRIBUTE_DATA("${entry1.ruleId}")
                                    }
                                    STIG_DATA {
                                        VULN_ATTRIBUTE("Rule_Ver")
                                        ATTRIBUTE_DATA("${entry1.ruleVer}")
                                    }
                                    STIG_DATA {
                                        VULN_ATTRIBUTE("Rule_Title")
                                        ATTRIBUTE_DATA("${entry1.ruleTitle}")
                                    }
                                    STIG_DATA {
                                        VULN_ATTRIBUTE("Vuln_Discuss")
                                        ATTRIBUTE_DATA("${entry1.vulnDiscuss}")
                                    }
                                    if (entry1.iaControls) {
                                        STIG_DATA {
                                            VULN_ATTRIBUTE("IA_Controls")
                                            ATTRIBUTE_DATA("${entry1.iaControls}")
                                        }
                                    } else {
                                        STIG_DATA {
                                            VULN_ATTRIBUTE("IA_Controls")
                                            ATTRIBUTE_DATA()
                                        }
                                    }

                                    STIG_DATA {
                                        VULN_ATTRIBUTE("Check_Content")
                                        ATTRIBUTE_DATA("${entry1.checkContent}")
                                    }
                                    STIG_DATA {
                                        VULN_ATTRIBUTE("Fix_Text")
                                        ATTRIBUTE_DATA("${entry1.fixText}")
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
                                        ATTRIBUTE_DATA("${entry1.responsibility}")
                                    }
                                    STIG_DATA {
                                        VULN_ATTRIBUTE("Security_Override_Guidance")
                                        ATTRIBUTE_DATA()
                                    }
                                    if (entry1.checkContentRef) {
                                        STIG_DATA {
                                            VULN_ATTRIBUTE("Check_Content_Ref")
                                            ATTRIBUTE_DATA("${entry1.checkContentRef}")
                                        }
                                    } else {
                                        STIG_DATA {
                                            VULN_ATTRIBUTE("Check_Content_Ref")
                                            ATTRIBUTE_DATA()
                                        }
                                    }
                                    if (entry1.weight) {
                                        STIG_DATA {
                                            VULN_ATTRIBUTE("Weight")
                                            ATTRIBUTE_DATA("${entry1.weight}")
                                        }
                                    } else {
                                        STIG_DATA {
                                            VULN_ATTRIBUTE("Weight")
                                            ATTRIBUTE_DATA()
                                        }
                                    }
                                    STIG_DATA {
                                        VULN_ATTRIBUTE("Class")
                                        ATTRIBUTE_DATA("${entry1.class1}")
                                    }
                                    STIG_DATA {
                                        VULN_ATTRIBUTE("STIGRef")
                                        ATTRIBUTE_DATA("${entry1.stigRef}")
                                    }
                                    STIG_DATA {
                                        VULN_ATTRIBUTE("TargetKey")
                                        ATTRIBUTE_DATA("${entry1.targetKey}")
                                    }
                                    if (entry1.cciRef) {
                                        STIG_DATA {
                                            VULN_ATTRIBUTE("CCI_REF")
                                            ATTRIBUTE_DATA("${entry1.cciRef}")
                                        }
                                    } else {
                                        STIG_DATA {
                                            VULN_ATTRIBUTE("CCI_REF")
                                            ATTRIBUTE_DATA()
                                        }
                                    }
                                    def comStigVulnStatus = AssetStigVulnStatus.findWhere(stigAsset: entry, stigVulnerability: entry1)
                                    if (comStigVulnStatus.status) {
                                        STATUS("${comStigVulnStatus.status}")
                                    }
                                    FINDING_DETAILS()
                                    if (comStigVulnStatus.comment) {
                                        COMMENTS("${comStigVulnStatus.comment}")
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
            }
        }
        return xmlHeaderString + "\n" + xmlHeaderString2 + "\n" + xmlWriter.toString()
    }

    //updates template STIG and STIG Vulnerability information when uploading .ckl file
    def updateStig(byte[] fileData, Stig stig) {
        List<StigVulnerability> currentStigVulnInstances = StigVulnerability.findAllWhere(stig: stig)
        def stigVulnNumList = []
        ArrayList currentStigVulnNumList = []
        if (currentStigVulnInstances) {
            for (instance in currentStigVulnInstances) {
                currentStigVulnNumList.add(instance.vulnNum)
            }
        }
        def contentString = new String(fileData)
        GPathResult checklist = new XmlSlurper().parseText(contentString)
        int vulnSize = checklist.STIGS.iSTIG.VULN.size()
        stig.stigCount = vulnSize
        stig.assetType = checklist.ASSET.ASSET_TYPE.text()
        int siDataSize = checklist.STIGS.iSTIG.STIG_INFO.SI_DATA.size()
        //parse through file to get STIG information
        for (int k = 0; k < siDataSize; k++) {
            if (checklist.STIGS.iSTIG.STIG_INFO.SI_DATA[k].SID_NAME.text() == "version") {
                def version = (checklist.STIGS.iSTIG.STIG_INFO.SI_DATA[k].SID_DATA.text())
                stig.version1 = version
            } else if (checklist.STIGS.iSTIG.STIG_INFO.SI_DATA[k].SID_NAME.text() == "classification") {
                stig.classification = checklist.STIGS.iSTIG.STIG_INFO.SI_DATA[k].SID_DATA.text()
            } else if (checklist.STIGS.iSTIG.STIG_INFO.SI_DATA[k].SID_NAME.text() == "customname") {
                stig.customName = checklist.STIGS.iSTIG.STIG_INFO.SI_DATA[k].SID_DATA.text()
            } else if (checklist.STIGS.iSTIG.STIG_INFO.SI_DATA[k].SID_NAME.text() == "stigid") {
                stig.stigId = checklist.STIGS.iSTIG.STIG_INFO.SI_DATA[k].SID_DATA.text()
            } else if (checklist.STIGS.iSTIG.STIG_INFO.SI_DATA[k].SID_NAME.text() == "description") {
                stig.description = checklist.STIGS.iSTIG.STIG_INFO.SI_DATA[k].SID_DATA.text()
            } else if (checklist.STIGS.iSTIG.STIG_INFO.SI_DATA[k].SID_NAME.text() == "filename") {
                stig.fileName = checklist.STIGS.iSTIG.STIG_INFO.SI_DATA[k].SID_DATA.text()
            } else if (checklist.STIGS.iSTIG.STIG_INFO.SI_DATA[k].SID_NAME.text() == "releaseinfo") {
                stig.releaseInfo = checklist.STIGS.iSTIG.STIG_INFO.SI_DATA[k].SID_DATA.text()
            } else if (checklist.STIGS.iSTIG.STIG_INFO.SI_DATA[k].SID_NAME.text() == "title") {
                stig.title = checklist.STIGS.iSTIG.STIG_INFO.SI_DATA[k].SID_DATA.text()
            } else if (checklist.STIGS.iSTIG.STIG_INFO.SI_DATA[k].SID_NAME.text() == "uuid") {
                stig.uuid = checklist.STIGS.iSTIG.STIG_INFO.SI_DATA[k].SID_DATA.text()
            } else if (checklist.STIGS.iSTIG.STIG_INFO.SI_DATA[k].SID_NAME.text() == "notice") {
                stig.notice = checklist.STIGS.iSTIG.STIG_INFO.SI_DATA[k].SID_DATA.text()
            } else if (checklist.STIGS.iSTIG.STIG_INFO.SI_DATA[k].SID_NAME.text() == "source") {
                stig.source = checklist.STIGS.iSTIG.STIG_INFO.SI_DATA[k].SID_DATA.text()
            }
        }
        stig.save(flush: true)

        //for each vulnerability
        String vulnNum
        String severity
        String groupTitle
        String ruleId
        String ruleVer
        String ruleTitle
        String vulnDiscuss
        String iaControls
        String checkContent
        String fixText
        String responsibility
        String class1
        String stigRef
        String status
        String comment
        String targetKey
        String checkContentRef
        String weight
        String cciRef
        for (int i = 0; i < vulnSize; i++) {
            vulnNum = ""
            severity = ""
            groupTitle = ""
            ruleId = ""
            ruleVer = ""
            ruleTitle = ""
            vulnDiscuss = ""
            iaControls = ""
            checkContent = ""
            fixText = ""
            responsibility = ""
            class1 = ""
            stigRef = ""
            targetKey = ""
            checkContentRef = ""
            weight = ""
            cciRef = ""
            comment = ""
            int stigDataSize = checklist.STIGS.iSTIG.VULN[i].STIG_DATA.size()

            for (def j = 0; j < stigDataSize; j++) {
                if (checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].VULN_ATTRIBUTE.text() == "Vuln_Num") {
                    vulnNum = checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].ATTRIBUTE_DATA.text()
                } else if (checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].VULN_ATTRIBUTE.text() == "Severity") {
                    severity = checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].ATTRIBUTE_DATA.text()
                } else if (checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].VULN_ATTRIBUTE.text() == "Group_Title") {
                    groupTitle = checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].ATTRIBUTE_DATA.text()
                } else if (checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].VULN_ATTRIBUTE.text() == "Rule_ID") {
                    ruleId = checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].ATTRIBUTE_DATA.text()
                } else if (checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].VULN_ATTRIBUTE.text() == "Rule_Ver") {
                    ruleVer = checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].ATTRIBUTE_DATA.text()
                } else if (checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].VULN_ATTRIBUTE.text() == "Rule_Title") {
                    ruleTitle = checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].ATTRIBUTE_DATA.text()
                } else if (checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].VULN_ATTRIBUTE.text() == "Vuln_Discuss") {
                    vulnDiscuss = checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].ATTRIBUTE_DATA.text()
                } else if (checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].VULN_ATTRIBUTE.text() == "IA_Controls") {
                    iaControls = checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].ATTRIBUTE_DATA.text()
                } else if (checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].VULN_ATTRIBUTE.text() == "Check_Content") {
                    checkContent = checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].ATTRIBUTE_DATA.text()
                } else if (checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].VULN_ATTRIBUTE.text() == "Fix_Text") {
                    fixText = checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].ATTRIBUTE_DATA.text()
                } else if (checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].VULN_ATTRIBUTE.text() == "Responsibility") {
                    responsibility = checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].ATTRIBUTE_DATA.text()
                } else if (checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].VULN_ATTRIBUTE.text() == "Check_Content_Ref") {
                    checkContentRef = checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].ATTRIBUTE_DATA.text()
                } else if (checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].VULN_ATTRIBUTE.text() == "Weight") {
                    weight = checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].ATTRIBUTE_DATA.text()
                } else if (checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].VULN_ATTRIBUTE.text() == "Class") {
                    class1 = checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].ATTRIBUTE_DATA.text()
                } else if (checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].VULN_ATTRIBUTE.text() == "STIGRef") {
                    stigRef = checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].ATTRIBUTE_DATA.text()
                } else if (checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].VULN_ATTRIBUTE.text() == "TargetKey") {
                    targetKey = checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].ATTRIBUTE_DATA.text()
                } else if (checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].VULN_ATTRIBUTE.text() == "CCI_REF") {
                    cciRef = checklist.STIGS.iSTIG.VULN[i].STIG_DATA[j].ATTRIBUTE_DATA.text()
                }
            }
            //Check to see if stigVuln exists using rule version
            def stigVulnInstance = StigVulnerability.findWhere(ruleVer: ruleVer, stig: stig)
            if (!stigVulnInstance) {
                //Second check to see if Stig Vulnerability matches rule title and STIG
                stigVulnInstance = StigVulnerability.findWhere(ruleTitle: ruleTitle, stig: stig)
                if (!stigVulnInstance) {
                    status = checklist.STIGS.iSTIG.VULN[i].STATUS.text()
                } else {
                    if (stigVulnInstance.status == "Not_Reviewed") {
                        status = checklist.STIGS.iSTIG.VULN[i].STATUS.text()
                    } else {
                        status = stigVulnInstance.status
                    }
                }
            } else {
                if (stigVulnInstance.status == "Not_Reviewed") {
                    status = checklist.STIGS.iSTIG.VULN[i].STATUS.text()
                } else {
                    status = stigVulnInstance.status
                }
            }
            if (checklist.STIGS.iSTIG.VULN[i].COMMENTS.text()) {
                comment = checklist.STIGS.iSTIG.VULN[i].COMMENTS.text()
            }
            if (stigVulnInstance) {
                currentStigVulnNumList.remove(stigVulnInstance.vulnNum)
                stigVulnInstance.vulnNum = vulnNum
                stigVulnInstance.severity = severity
                stigVulnInstance.groupTitle = groupTitle
                stigVulnInstance.ruleId = ruleId
                stigVulnInstance.ruleVer = ruleVer
                stigVulnInstance.ruleTitle = ruleTitle
                stigVulnInstance.vulnDiscuss = vulnDiscuss
                stigVulnInstance.iaControls = iaControls
                stigVulnInstance.checkContent = checkContent
                stigVulnInstance.fixText = fixText
                stigVulnInstance.responsibility = responsibility
                stigVulnInstance.class1 = class1
                stigVulnInstance.stigRef = stigRef
                stigVulnInstance.status = status
                stigVulnInstance.targetKey = targetKey
                //if stigVulnInstance comments do not exist
                if (!stigVulnInstance.comment) {
                    //If comments are retrieved from input
                    if (comment) {
                        stigVulnInstance.comment = comment
                        //else assign comments to "NA"
                    } else {
                        stigVulnInstance.comment = "None"
                    }
                }
                stigVulnInstance.stig = stig
                stigVulnInstance.checkContentRef = checkContentRef
                stigVulnInstance.weight = weight
                stigVulnInstance.cciRef = cciRef
                stigVulnInstance.save()
            } else {
                def stigVulnerability = new StigVulnerability(vulnNum: vulnNum, severity: severity, groupTitle: groupTitle,
                        ruleId: ruleId, ruleVer: ruleVer, ruleTitle: ruleTitle, vulnDiscuss: vulnDiscuss, iaControls: iaControls, checkContent: checkContent,
                        fixText: fixText, responsibility: responsibility, class1: class1, stigRef: stigRef, status: status, stig: stig,
                        targetKey: targetKey, checkContentRef: checkContentRef, weight: weight, comment: comment, cciRef: cciRef)
                stigVulnerability.save()
            }
        }
        if (currentStigVulnNumList) {
            for (entry in currentStigVulnNumList) {
                StigVulnerability stigVuln1 = StigVulnerability.findWhere(vulnNum: entry)
                List<AssetStigVulnStatus> assetStigVulnStatusInstances = AssetStigVulnStatus.findAllWhere(stigVulnerability: stigVuln1)
                if (assetStigVulnStatusInstances) {
                    //find all entries of the vulnerability in AssetStigVulnStatus
                    assetStigVulnStatusInstances = AssetStigVulnStatus.findAllWhere(stigVulnerability: stigVuln1)
                    if (assetStigVulnStatusInstances) {
                        for (entry1 in assetStigVulnStatusInstances) {
                            //delete entry from AssetStigVulnStatus
                            entry1.delete()
                        }
                    }
                    //delete any Mitigations with this STIG Vulnerability
                    def mitigations = MitigationStig.list()
                    for (entry1 in mitigations) {
                        if (entry1.stigVulnerability == stigVuln1) {
                            entry1.delete()
                        }
                    }
                    //delete entry from STIG Vulnerabilities
                    stigVuln1.delete()
                }
            }
        }
    }

    //Deletes entries from AssetStigVulnStatus and StigItemCheck for a STIG
    def deleteStigEntry(Long id) {
        Stig stig = Stig.findWhere(id: id)
        List<StigVulnerability> StigVulnEntries = StigVulnerability.findAllWhere(stig: stig)
        if (StigVulnEntries) {
            for (entry in StigVulnEntries) {
                def compStigVulnStatusValues = AssetStigVulnStatus.findAllWhere(stigVulnerability: entry)
                if (compStigVulnStatusValues) {
                    //delete AssetStigVulnStatus values where STIG Vulnerability = entry
                    for (compStigVulnStatusValue in compStigVulnStatusValues) {
                        compStigVulnStatusValue.delete()
                    }
                }
                def stigItemCheckValues = StigItemCheck.findAllWhere(vulnNum: entry.vulnNum)
                if (stigItemCheckValues) {
                    //delete StigItemCheck values that match entry's vulnNum
                    for (stigItemCheckValue in stigItemCheckValues) {
                        stigItemCheckValue.delete()
                    }
                }
                entry.delete()
            }
        }
        stig.delete()
    }

    //Get Audit results where asset posture is true
    def getAuditResults(Map map) {
        List<Asset> assets = Asset.findAllWhere(posture: true)
        for (asset in assets) {
            String id = asset.id.toString()
            getAuditUpdate(map, id)
        }
    }

    //Get audit vulnerabilities for one asset
    @Transactional
    def getAuditUpdate(Map map, String id) {
        String token = "${map.get("token")}"
        String cookie = "${map.get("cookie")}"
        Long idLong = Long.valueOf(id)
        Asset asset = Asset.findWhere(id: idLong)
        checkASVS(asset)
        if (cookie != "null") {
            String repositories = (grailsApplication.config.getProperty('acasAuditRepository', String.class))
            def sslContext = SSLContexts.createSystemDefault()
            String json = ""
            //asset compliance vulnerabilities using filters IP address, and severity
            def query = '{ ' +
                    '"query": {' +
                    '"type":"vuln",' +
                    '"tool":"vulndetails",' +
                    '"filters": [{' +
                    '"id":"repository", ' +
                    '"filterName":"repositoryIDs",' +
                    '"operator":"=",' +
                    '"value":"' + repositories + '"' +
                    '}, ' +
                    '{' +
                    '"id":"ip", ' +
                    '"filterName":"ip",' +
                    '"operator":"=",' +
                    '"value":"' + asset.ipAddress + '"' +
                    '}, ' +
                    '{' +
                    '"id":"familyID", ' +
                    '"filterName":"familyID",' +
                    '"operator":"=",' +
                    '"value":"0"' +
                    '}' +
                    ']' +
                    '},' +
                    '"type":"vuln", ' +
                    '"tool":"vulndetails", ' +
                    '"sourceType":"cumulative", ' +
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
                log.error "Failed retrieving asset list"
            } finally {
                httpClient.close()
            }
            def jsonSlurper = new JsonSlurper()
            def json1 = jsonSlurper.parseText(json)
            List<String> results = json1.response.results
            results.each { result ->
                if (result.family.name == "N/A") {
                    if (result.pluginText.contains("<cm:compliance-actual-value>")) {
                        String result1 = result.pluginText.replaceAll("cm:compliance", "compliance")
                        String pluginTextValue2 = result1.replaceAll("&", "")
                        String pluginTextValue3 = "<root>" + pluginTextValue2 + "</root>"
                        GPathResult rootNode = new XmlSlurper().parseText(pluginTextValue3)
                        //retrieve result
                        def actualValue = rootNode."compliance-result".text()
                        //retrieve vulnNum
                        String xref = result.xref
                        String[] vulnNumArray = xref.split(",")
                        String vulnNum = ""
                        String tenable = ""
                        for (entry in vulnNumArray) {
                            if (entry.startsWith("Vuln-ID")) {
                                vulnNum = entry.replaceAll("Vuln-ID #", "")
                            } else if (entry.startsWith("DISA_Benchmark")) {
                                tenable = entry.replaceAll("DISA_Benchmark #", "")
                            }
                        }
                        log.warn("Tenable: " + tenable)
                        if (tenable) {
                            Stig stig = Stig.findWhere(tenable: tenable)
                            if (stig) {
                                StigAsset stigAsset = StigAsset.findWhere(stig: stig, asset: asset)
                                if (stigAsset) {
                                    //retrieve scan date
                                    String lastSeenString = result.lastSeen.toString()
                                    Long lastSeenLong = Long.valueOf(lastSeenString)
                                    SimpleDateFormat sdf = new SimpleDateFormat("MM/dd/yyyy")
                                    String scanDate = sdf.format(new Date(lastSeenLong * 1000L))
                                    StigVulnerability stigVulnerability = StigVulnerability.findWhere(vulnNum: vulnNum, stig: stig)
                                    if (stigVulnerability) {
                                        AssetStigVulnStatus assetStigVulnStatus = AssetStigVulnStatus.findWhere(asset: asset, stigVulnerability: stigVulnerability)
                                        try {
                                            if (assetStigVulnStatus) {
                                                if (actualValue == "FAILED") {
                                                    assetStigVulnStatus.comment = "ACAS Results for scan on ${scanDate} FAILED"
                                                    assetStigVulnStatus.status = "Open"
                                                    assetStigVulnStatus.reviewed = true
                                                } else if (actualValue == "PASSED") {
                                                    assetStigVulnStatus.comment = "ACAS Results for scan on ${scanDate} PASSED"
                                                    assetStigVulnStatus.status = "NotAFinding"
                                                    assetStigVulnStatus.reviewed = true
                                                } else if (actualValue == "NOT APPLICABLE") {
                                                    assetStigVulnStatus.comment = "ACAS Results for scan on ${scanDate}: NOT_APPLICABLE"
                                                    assetStigVulnStatus.status = "Not_Applicable"
                                                    assetStigVulnStatus.reviewed = true
                                                }
                                                assetStigVulnStatus.save()
                                            } else {
                                                AssetStigVulnStatus assetStigVulnStatus1 = new AssetStigVulnStatus()
                                                assetStigVulnStatus1.asset = asset
                                                assetStigVulnStatus1.stigVulnerability = stigVulnerability
                                                assetStigVulnStatus1.stigAsset = stigAsset
                                                if (actualValue == "FAILED") {
                                                    assetStigVulnStatus1.comment = "ACAS Results for scan on ${scanDate}: FAILED"
                                                    assetStigVulnStatus1.status = "Open"
                                                    assetStigVulnStatus1.reviewed = true
                                                } else if (actualValue == "PASSED") {
                                                    assetStigVulnStatus1.comment = "ACAS Results for scan on ${scanDate}: PASSED"
                                                    assetStigVulnStatus1.status = "NotAFinding"
                                                    assetStigVulnStatus1.reviewed = true
                                                } else if (actualValue == "NOT APPLICABLE") {
                                                    assetStigVulnStatus1.comment = "ACAS Results for scan on ${scanDate}: NOT_APPLICABLE"
                                                    assetStigVulnStatus1.status = "Not_Applicable"
                                                    assetStigVulnStatus1.reviewed = true
                                                }
                                                assetStigVulnStatus1.save()
                                            }
                                        } catch (e) {
                                            log.error(e.getMessage())
                                        }
                                    } else {
                                        log.warn("No STIG Vulnerability for Vuln Num: ${vulnNum}")
                                    }
                                } else {
                                    log.error("No STIG Asset entry for STIG: ${stig.title} and Asset: ${asset.name}")
                                }
                            } else {
                                log.error("No STIG Template for STIG: ${tenable}")
                            }
                        } else {
                            log.warn("No DISA Benchmark Info.")
                        }
                    }
                }
            }
            updateAssetStigReview(asset)
            return asset
        } else {
            log.error("No cookie available for benchmark scan update")
        }
    }

    def updateAssetStigReview(asset) {
        def assetStigs = StigAsset.findAllWhere(asset: asset)
        for (assetStig in assetStigs) {
            def assetStigVulnStatusReviewed = true
            def assetStigVulnStatuses = AssetStigVulnStatus.findAllWhere(stigAsset: assetStig)
            for (assetStigVulnStatus in assetStigVulnStatuses) {
                if (assetStigVulnStatusReviewed) {
                    if (!assetStigVulnStatus.reviewed) {
                        assetStigVulnStatusReviewed = false
                    }
                }
            }
            if (assetStigVulnStatusReviewed) {
                assetStig.complete = true
                assetStig.save()
            } else {
                assetStig.complete = false
                assetStig.save()
            }
        }
    }

    def checkASVS(Asset asset) {
        List<StigAsset> stigAssetList = StigAsset.findAllWhere(asset: asset)
        for (stigAsset in stigAssetList) {
            if (stigAsset.stig.tenable) {
                List<AssetStigVulnStatus> asvsList = AssetStigVulnStatus.findAllWhere(stigAsset: stigAsset, asset: asset)
                List asvsStigVulnList = []
                for (asvs in asvsList) {
                    asvsStigVulnList += asvs.stigVulnerability
                }
                List<StigVulnerability> stigVulnList = StigVulnerability.findAllWhere(stig: stigAsset.stig)
                asvsStigVulnList.intersect(stigVulnList).each { asvsStigVulnList.remove(it); stigVulnList.remove(it) }
                if (asvsStigVulnList.size() > 0) {
                    for (asvsStigVuln in asvsStigVulnList) {
                        AssetStigVulnStatus asvs1 = AssetStigVulnStatus.findWhere(stigVulnerability: asvsStigVuln, asset: stigAsset.asset, stigAsset: stigAsset)
                        asvs1.delete(flush: true)
                    }
                } else if (stigVulnList.size() > 0) {
                    for (stigVuln in stigVulnList) {
                        new AssetStigVulnStatus(stigAsset: stigAsset, stigVulnerability: stigVuln, asset: stigAsset.asset, comment: stigVuln.comment, status: stigVuln.status).save(flush: true)
                    }
                }
            }
        }
    }

    //Import a zip file containing all STIGs and processs them
    def updateTemplate(String fileName) {
        List fileNameList = []
        List entryList = []
        //home/oracle/.grails/tmp/zipFile/
        def baseDir = (grailsApplication.config.getProperty('baseDir', String.class))
        def classification = (grailsApplication.config.getProperty('fileClassification', String.class))
        //name a temp file to store uploaded zip file
        def zipFile = new ZipFile(new File("${baseDir}data.zip"))
        //process each STIG in the zip file
        zipFile.entries().each {
            if (!it.directory) {
                fileNameList += it.name
            }
            def path = Paths.get(baseDir + it.name)
            //creates the first subdirectory that contains all the zipped STIG zip files
            if (it.directory) {
                Files.createDirectories(path)
            } else {
                def parentDir = path.getParent()
                if (!Files.exists(parentDir)) {
                    Files.createDirectories(parentDir)
                }
                Files.copy(zipFile.getInputStream(it), path)
            }
        }
        for (entry in fileNameList) {
            def fileLocation = baseDir + entry
            new ZipFile(fileLocation).withCloseable { zip ->
                zip.entries().toList().each { entry1 ->
                    if (entry1.name.endsWith("-xccdf.xml")) {
                        zip.getInputStream(entry1).withCloseable { input ->
                            String entry1String = entry1.toString()
                            def entry1List = entry1String.split("/")
                            def entry1ListSize = entry1List.size()
                            def newEntry = entry1List[entry1ListSize - 1]
                            entryList += newEntry
                            def xmlFile = baseDir + newEntry
                            def outputFile = new File(xmlFile)
                            outputFile.withOutputStream { output ->
                                input.eachByte { byte it1 ->
                                    output.write(it1)
                                }
                            }
                        }
                    }
                }
            }
        }
        //Clean up zipFile directory
        //remove data.zip file
        File dataFile = new File (baseDir + "data.zip")
        dataFile.delete()
        //remove extension from each file in base directory
        def fileName1 = FilenameUtils.removeExtension(fileName)
        def dir = new File(baseDir.concat(fileName1))
        // remove each zip file in baseDirectory/<filename> directory
        dir.eachFileRecurse(FileType.FILES) { file ->
            file.delete()
        }
        // remove baseDirectory/<filename> sub-directories
        dir.eachFileRecurse(FileType.DIRECTORIES) { dir1 ->
            dir1.delete()
        }
        //remove the filename directory
        dir.delete()

        new File(baseDir).eachFile { file ->
            //setup file to be an XML file with root tag (Benchmark)
            def Benchmark = new XmlSlurper().parse(file)
            //Get STIG title
            def title = Benchmark.title.text()
            //Find STIG in CVMT that matches title
            Stig stig = Stig.findWhere(title: title)
            if (stig){
                //Get STIG Vulnerabilities to be used to determine if a STIG vulnerability is no longer in the new STIG
                List <StigVulnerability> stigVulnList = StigVulnerability.findAllWhere (stig: stig)
                //compare stig title to title in xml file
                if (stig.title == title) {
                    //Get Release Info from xml file
                    String plainText = Benchmark.'plain-text'.find { it.@id.text() == "release-info" }.text()
                    //compare xml release info with CVMT release info
                    if (plainText != stig.releaseInfo) {
                        log.warn ("Updating ${stig.title} to release ${plainText}")
                        stig.title = Benchmark.title.text()
                        stig.releaseInfo = plainText
                        stig.version1 = Benchmark.version.text()
                        stig.save(flush:true)
                        //Get each STIG vulnerability from XML file
                        Benchmark.Group.each { stigVulnerability1 ->
                            String ruleVer = stigVulnerability1.Rule.version.text()
                            String ruleTitle = stigVulnerability1.Rule.title.text()
                            //Get STIG Vulnerability in CVMT that matches STIG  and Group Title
                            StigVulnerability stigVulnerability = StigVulnerability.findWhere(stig: stig, ruleVer: ruleVer)
                            if (!stigVulnerability) {
                                stigVulnerability = StigVulnerability.findWhere(stig: stig, ruleTitle: ruleTitle)
                            }
                            if (stigVulnerability) {
                                //Remove from list each STIG Vulnerability
                                stigVulnList -= stigVulnerability
                                String description = stigVulnerability1.Rule.description.text()
                                stigVulnerability.vulnDiscuss = description.takeBetween("<VulnDiscussion>", "</VulnDiscussion>")
                                stigVulnerability.responsibility = description.takeBetween("<Responsibility>","</Responsibility>")
                                stigVulnerability.iaControls = description.takeBetween("<IAControls>","</IAControls>")
                                stigVulnerability.ruleTitle = ruleTitle
                                stigVulnerability.ruleVer = ruleVer
                                stigVulnerability.ruleId = stigVulnerability1.Rule.@id
                                stigVulnerability.severity = stigVulnerability1.Rule.@severity
                                stigVulnerability.weight = stigVulnerability1.Rule.@weight
                                stigVulnerability.class1 = classification
                                stigVulnerability.vulnNum = stigVulnerability1.@id
                                stigVulnerability.fixText = stigVulnerability1.Rule.fixtext.text()
                                stigVulnerability.checkContent = stigVulnerability1.Rule.check.'check-content'.text()
                                stigVulnerability.severity = stigVulnerability1.Rule.@severity
                                stigVulnerability.groupTitle = stigVulnerability1.title.text()
                                stigVulnerability.targetKey = stigVulnerability1.Rule.reference.identifier.text()
                                stigVulnerability.stigRef = title + " :: Version: " + stig.version1 + ", " + plainText
                                stigVulnerability.cciRef = stigVulnerability1.Rule.ident.find { it.@system = 'http://cyber.mil/cci' }.text()
                                stigVulnerability.save()
                            } else {
                                StigVulnerability stigVuln = new StigVulnerability()
                                String description = stigVulnerability1.Rule.description.text()
                                stigVuln.vulnDiscuss = description.takeBetween("<VulnDiscussion", "</VulnDiscussion>")
                                stigVuln.responsibility = description.takeBetween("<Responsibility>","</Responsibility>")
                                stigVuln.iaControls = description.takeBetween("<IAControls>","</IAControls>")
                                stigVuln.ruleTitle = ruleTitle
                                stigVuln.ruleVer = ruleVer
                                stigVuln.stig = stig
                                stigVuln.vulnNum = stigVulnerability1.@id
                                stigVuln.fixText = stigVulnerability1.Rule.fixtext.text()
                                stigVuln.checkContent = stigVulnerability1.Rule.check.'check-content'.text()
                                stigVuln.checkContentRef = stigVulnerability1.Rule.check.'check-content-ref'.@name
                                stigVuln.ruleId = stigVulnerability1.Rule.@id
                                stigVuln.severity = stigVulnerability1.Rule.@severity
                                stigVuln.weight = stigVulnerability1.Rule.@weight
                                stigVuln.groupTitle = stigVulnerability1.title.text()
                                stigVuln.stigRef = title + " :: Version: " + stig.version1 + ", " + plainText
                                stigVuln.targetKey = stigVulnerability1.Rule.reference.identifier.text()
                                stigVuln.class1 = classification
                                stigVuln.status = "Not_Reviewed"
                                stigVuln.cciRef = stigVulnerability1.Rule.ident.find {it.@system = 'http://cyber.mil/cci'}.text()
                                stigVuln.save()
                            }
                        }
                        for (stigVuln in stigVulnList) {
                            try {
                                def asvsEntries = AssetStigVulnStatus.findAllWhere(stigVuln: stigVuln)
                                if (asvsEntries){
                                    for (entry in asvsEntries){
                                        entry.delete(flush:true)
                                    }
                                }
                                stigVuln.delete()
                            } catch ( e){
                                e.getMessage()
                            }
                        }
                    } else {
                        log.warn "No update to STIG: ${stig.title}"
                    }
                }
            }
        }
        //removes downloaded xml files
        new File (baseDir).eachFileRecurse(FileType.FILES) { file ->
            file.delete()
        }
    }
}