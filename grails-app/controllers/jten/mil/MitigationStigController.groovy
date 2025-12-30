package jten.mil


import grails.validation.ValidationException
import grails.gorm.transactions.Transactional
import static org.springframework.http.HttpStatus.*

@Transactional
class MitigationStigController {
    def mitigationService

    def show (Long id){
        MitigationStig mitigationStig = MitigationStig.findWhere(id: id)
        respond mitigationStig
    }

    def save(MitigationStig mitigationStig) {
        if (mitigationStig == null) {
            render "status: NOT_FOUND"
            return
        }
        try {
            mitigationStig.save()
        } catch (ValidationException e) {
            e.stackTrace
            respond mitigationStig.errors, view:'create'
            return
        }
        respond mitigationStig, [status: CREATED]
    }

    def update(MitigationStig mitigationStig) {
        if (mitigationStig == null) {
            render "status: NOT_FOUND"
            return
        }
        try {
            mitigationStig.save()
        } catch (ValidationException e) {
            e.suppressed
            respond mitigationStig.errors, view:'edit'
            return
        }
        respond mitigationStig, [status: OK, view:"show"]
    }

    def delete(Long id) {
        MitigationStig mitigationStig = MitigationStig.findWhere(id: id)
        mitigationStig.delete()
        render "status: NO_CONTENT"
    }

    def getStigMit() {
        String assetStigVulnStatusId = params.assetStigVulnStatusId
        respond (mitigationService.getStigMit(assetStigVulnStatusId))
    }

    def getStigMits() {
        respond(mitigationService.getStigMits())
    }

}