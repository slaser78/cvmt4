package jten.mil

import grails.async.Promise
import grails.gorm.transactions.ReadOnly
import grails.gorm.transactions.Transactional
import grails.validation.ValidationException
import static org.springframework.http.HttpStatus.OK

@ReadOnly
class AssetStigVulnStatusController {
    def assetStigVulnStatusService

    //Get one Asset STIG Vulnerability Status entry using one STIG Asset Entry and one STIG Vulnerability entry
    def getAssetStigVulnStatusEntry(){
        String stigVuln = params.stigVuln
        String stigAsset = params.stigAsset
        respond (assetStigVulnStatusService.getAssetStigVulnStatusEntry(stigVuln, stigAsset))
    }

    //Get all Asset STIG Vulnerability Status entries for one STIG Asset Entry
    @Transactional
    def getAssetStigVulnStatusEntries() {
        String stigAsset = params.stigAsset
        respond (assetStigVulnStatusService.getAssetStigVulnStatusEntries(stigAsset))
    }

    //Update Asset STIG Vulnerability Status entry
    @Transactional
    def update(AssetStigVulnStatus assetStigVulnStatus) {
        try {
            assetStigVulnStatus.save()
        } catch (ValidationException e) {
            e.stackTrace
            respond assetStigVulnStatus.errors
            return
        }
        respond assetStigVulnStatus, [status: OK, view:"show"]
    }


    @Transactional
    def setAssetStigVulnStatusEntry(){
        respond (assetStigVulnStatusService.setAssetStigVulnStatusEntry(request.JSON))
    }

    @Transactional
    def updateStigAsset() {
        respond (assetStigVulnStatusService.setAssetStigVulnStatusEntry(request.JSON))
    }

    def getAssetStigVulnStatuses() {
        def asvs = assetStigVulnStatusService.getAssetStigVulnStatuses(params)
        if (asvs) {
            respond asvs
        } else {
            respond ("No Entries")
        }
    }

    def getAssetStigVulnStatus() {
        String assetStigVulnStatusIdString = params.assetStigVulnStatusId.toString()
        respond(assetStigVulnStatusService.getAssetStigVulnStatus(assetStigVulnStatusIdString))
    }

    def getAsvsCount() {
        def asvsCount = assetStigVulnStatusService.getAsvsCount(params)
        respond (["asvsCount":asvsCount])
    }

    @Transactional
    def setAsvsFalse() {
        Promise p = task {
            log.warn("Started Set All AssetStigVulnStatus Reviewed Fields to False.")
            assetStigVulnStatusService.setAsvsFalse()
        }
        p.onError { Throwable err ->
            log.error "An error occurred ${err.message}"
        }
        p.onComplete { result ->
            log.warn("Finished Setting All AssetStigVulnStatus Reviewed Fields to False.")
        }
        redirect (controller: "vulnerability", action: "maintenance")
    }

    @Transactional
    def importScap() {
        def file = request.getFile('file')
        def stigAsset = params.stigAsset
        byte[] fileByte = file.getBytes()
        if(file.empty){
            flash.message = "File cannot be empty"
            redirect (action:'stigExport')
        }
        else {
            String stigAssetString = stigAsset.toString()
            assetStigVulnStatusService.importScap(fileByte, stigAssetString)
        }
        respond "Complete"
    }

    def getStigVulnDetail() {
        respond (assetStigVulnStatusService.getStigVulnDetail(params.vulnDetailId))
    }
}
