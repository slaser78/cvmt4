package jten.mil


import grails.gorm.transactions.ReadOnly
import grails.gorm.transactions.Transactional
import grails.validation.ValidationException
import static org.springframework.http.HttpStatus.*

@ReadOnly
class StigAssetController {
    def stigAssetService
    def acasRestService

    def getStigAssets() {
        respond(stigAssetService.getStigAssets())
    }

    def show(StigAsset stigAsset) {
        respond stigAsset
    }

    @Transactional
    def save(StigAsset stigAsset) {
        if (stigAsset == null) {
            render "status: NOT_FOUND"
            return
        }
        try {
            stigAsset.save(flush:true)
            stigAssetService.createASVS(stigAsset)
        } catch (e) {
            log.error "Error: " + e.getMessage()
            return
        }
        respond stigAsset
    }

    @Transactional
    def update(StigAsset stigAsset) {
        try {
            stigAsset.save(flush: true)
        } catch (ValidationException e) {
            e.suppressed
            respond stigAsset.errors, view: 'edit'
            return
        }
        respond stigAsset, [status: OK, view: "show"]
    }

    @Transactional
    def delete(Long id) {
        if (id == null) {
            render "status: NOT_FOUND"
            return
        }
        stigAssetService.deleteStigAssetCheckValues(id)
        StigAsset stigAsset1 = StigAsset.findWhere(id: id)
        stigAsset1.delete()
        render "status: NO_CONTENT"
    }

    def stigSummary() {
        respond(stigAssetService.stigSummary())
    }

    @Transactional
    def getStigAssetComplete() {
        String stigAssetString = params.stigAsset.toString()
        respond stigAsset2Service.updateSaComplete(stigAssetString)
    }

    def exportSAChecklist() {
        def stigAssets = request.JSON
        stigAssetService.exportSAChecklist(stigAssets)
        def file = new File(grailsApplication.config.getProperty('tempLocation',String.class)+"zipFile/StigAssets.zip")
        if (file.exists()) {
            response.setHeader "Content-Disposition", "attachment;filename=StigAsset.zip"
            response.setContentType("application/octet-stream")
            response.outputStream << file.newInputStream()
        }
        new File(grailsApplication.config.getProperty('tempLocation',String.class)+"input").eachFile() {
            file1-> file1.delete()
        }
        new File (grailsApplication.config.getProperty('tempLocation',String.class)+"zipFile").eachFile() {
            file2-> file2.delete()
        }
    }

    @Transactional
    def getPosture() {
        stigAssetService.getPosture(acasRestService.getConnection())
        respond "Complete"
    }

    @Transactional
    def getPosture1() {
        String idString = params.id.toString()
        stigAssetService.getPosture1(acasRestService.getConnection(), idString)
        respond "Complete"
    }
}