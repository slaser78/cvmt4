package jten.mil

import grails.gorm.transactions.Transactional
import grails.validation.ValidationException
import static grails.async.Promises.*
import static org.springframework.http.HttpStatus.*
import grails.gorm.transactions.ReadOnly

@ReadOnly
class AssetController {
    def assetService
    def scanService
    def elasticService
    def lookupService
    def stigService

    @SuppressWarnings('GroovyAssignabilityCheck')
    def index() {
        respond Asset.list()
    }

    def getAssetDns () {
        String idString = params.id.toString()
        respond lookupService.getAssetDns(idString)
    }

    def show(Long id) {
        Asset asset = Asset.findWhere (id: id)
        respond asset
    }

    @Transactional
    def save(Asset asset) {
        if (asset == null) {
            render "status: NOT_FOUND"
            return
        }
        try {
            assetService.save(asset)
        } catch (ValidationException e) {
            e.suppressed
            respond asset.errors
            return
        }
        respond asset, [status: CREATED]
    }

    @Transactional
    def update(Asset asset) {
        if (asset == null) {
            render "status: NOT_FOUND"
            return
        }
        try {
            log.warn ("Updated asset: ${asset.name}")
            asset.save()
        } catch (ValidationException e) {
            e.suppressed
            respond asset.errors
            return
        }
        respond asset, [status: OK, view:"show"]
    }

    @Transactional
    def delete(Long id) {
        if (id == null) {
            render "status: NOT_FOUND"
            return
        }
        Asset asset = Asset.findWhere(id: id)
        asset.delete()
        respond "status: NO_CONTENT"
    }

    @Transactional
    def getAssets() {
        log.warn  ("Started Get Assets")
        def p = task {
            assetService.getAssets(AcasRestService.getConnection())
        }
        p.onError { Throwable err ->
            log.warn "An error occurred ${err.message}"
        }
        p.onComplete { result ->
            log.warn("Finished Get Assets")
        }
        respond "Complete"
    }

    @Transactional
    def getScore() {
        log.warn ("Start Get Asset-Vulnerability Scores.")
        def p = task {
            assetService.getScore()
        }
        p.onError { Throwable err ->
            log.warn "An error occurred ${err.message}"
        }
        p.onComplete { result ->
            log.warn("Finish Get Asset-Vulnerability Scores")
        }
        respond "Complete"
    }

    @Transactional
    def lookupAsset() {
        log.warn (("Started asset lookups"))
        LookupService.getName()
        log.warn ( "Finished asset lookups.")
        respond "Completed"
    }

    @Transactional
    def deleteBulkAsset() {
        def file = request.getFile('file')
        def fileNameValue = file.originalFilename.toString()
        if(file.empty){
            log.warn( "File empty.")
        }
        else if (fileNameValue.endsWith('.csv')){
            def fileData = file.getBytes()
            try {
                AssetService.deleteBulkAsset(fileData)
            }  catch (ValidationException e) {
                e.suppressed
            }
        }
        respond "Completed"
    }

    //Manually upload asset information in .csv format
    @Transactional
    def uploadAsset(){
        def file = request.getFile('file')
        String fileNameValue = file.originalFilename.toString()
        if(file.empty){
            log.warn( "File empty.")
        }
        else if (fileNameValue.endsWith('.csv')){
            def fileData = file.getBytes()
            try {
                log.warn ("Start Uploading asset csv file.")
                AssetService.uploadAsset(fileData)
                log.warn ("Finish Uploading asset csv file.")
            }
            catch (ValidationException e) {
                e.suppressed
            }
        }
        respond "Complete"
    }

    //Get Asset Scan Details for all assets
    @Transactional
    def getAssetScanDetails1 () {
        log.warn ("Start Get Asset Scan Details")
        scanService.getAssetScanDetails1(acasRestService.getConnection())
        log.warn ("Finish Get Asset Scan Details")
        respond "Complete"
    }

    //Get VulnDetail Details for all Assets
    @Transactional
    def getScanDetails() {
        log.warn ("Start Set Patch Vulnerability Scan Details.")
        scanService.getScanDetails(acasRestService.getConnection())
        log.warn("Finish Set Patch Vulnerability Scan Details.")
        respond "Complete"
    }

    //get audit update information for asset from ACAS
    @Transactional
    def getAuditUpdate() {
        log.warn ("Start Get Audit Update.")
        String idString = params.id.toString()
        Asset asset = StigService.getAuditUpdate(acasRestService.getConnection(), idString)
        log.warn("Finish Get Audit Update.")
        respond asset
    }

    def getAuditResults() {
        def p = task {
            log.warn ("Start Get Audit Results")
            stigService.getAuditResults(acasRestService.getConnection())
        }
        p.onError { Throwable err ->
            log.error "An error occurred ${err.message}"
        }
        p.onComplete { result ->
            log.warn "Finish Get Audit Results"
        }
        respond "Complete"
    }

    def elasticPatchUpload() {
        log.warn "Start Patch Vuln Elastic Import"
        elasticService.elasticPatchUpload()
        log.warn "Finish Patch Vuln Elastic Import"
        respond "Complete"
    }

    def elasticStigUpload() {
        log.warn "Start STIG Elastic Import"
        elasticService.elasticStigUpload()
        log.warn "Finish STIG Elastic Import"
        respond "Complete"
    }

    def elasticAssetUpload() {
        log.warn "Start Asset Elastic Import"
        elasticService.elasticAssetUpload()
        log.warn "Finish Asset Elastic Import"
        respond "Complete"
    }

    def elasticDeviceTypesUpload() {
        def p = task {
            log.warn "Start Upload Device Types STIG Summary to Elastic"
            elasticService.elasticDeviceTypeUpload()
        }
        p.onError { Throwable err ->
            log.error "An error occurred ${err.message}"
        }
        p.onComplete { result ->
            log.warn "Finish Upload Device Types STIG Summary to Elastic"
        }
        redirect (controller: "vulnerability", action: "maintenance")
    }

    @Transactional
    def getOpSystems() {
        log.warn ("Start Get Operating Systems")
        assetService.getOpSystems(acasRestService.getConnection())
        log.warn ("Finish Get Operating Systems")
        respond "Complete"
    }

    @Transactional
    def checkAcas() {
        log.warn ("Start check CVMT for assets no longer in ACAS")
        assetService.checkAcas(acasRestService.getConnection())
        log.warn ("Complete check CVMT for assets no longer in ACAS")
        respond "Complete"
    }
}