package jten.mil

import grails.validation.ValidationException
import static org.springframework.http.HttpStatus.CREATED
import static org.springframework.http.HttpStatus.OK
import grails.gorm.transactions.ReadOnly
import grails.gorm.transactions.Transactional

@ReadOnly
class CustomStigMitController {
    def mitigationService

    def index() {
        respond customStigMit
    }

    def show(Long id) {
        CustomStigMit customStigMit = CustomStigMit.findWhere(id: id)
        respond customStigMit
    }

    @Transactional
    def save(CustomStigMit customStigMit) {
        try {
            customStigMit.save()
        } catch (ValidationException e) {
            log.error ("Custom Stig Mit Save Error: " + e.getMessage())
            respond customStigMit.errors
            return
        }
        respond customStigMit, [status: CREATED]
    }

    @Transactional
    def update(CustomStigMit customStigMit) {
        if (customStigMit == null) {
            render "status: NOT_FOUND"
            return
        }
        try {
            customStigMit.save()
        } catch (ValidationException e) {
            e.suppressed
            respond customStigMit.errors
            return
        }
        respond customStigMit, [status: OK, view:"show"]
    }

    @Transactional
    def delete(Long id) {
        CustomStigMit customStigMit1 = CustomStigMit.findWhere(id: id)
        if (id == null || customStigMit.delete() == null) {
            render "status: NOT_FOUND"
            return
        }
        customStigMit1.delete()
        render "status: NO_CONTENT"
    }

    def getCustomStigMit(){
        String idString = params.id.toString()
        respond (mitigationService.getCustomStigMit(idString))
    }

    def getCustomStigMits(){
        respond (mitigationService.getCustomStigMits())
    }

    @Transactional
    def setCustomStigMit() {
        def valuesReturned = request.JSON
        mitigationService.setCustomStigMit(valuesReturned)
        respond "Complete"
    }
}