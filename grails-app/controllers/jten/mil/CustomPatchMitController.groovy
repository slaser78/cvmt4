package jten.mil

import grails.validation.ValidationException
import static org.springframework.http.HttpStatus.CREATED
import grails.gorm.transactions.ReadOnly
import grails.gorm.transactions.Transactional

@ReadOnly
class CustomPatchMitController {
    def mitigationService
    def vulnerabilityService

    def index(Integer max) {
        respond CustomPatchMit.list(params)
    }

    def show(Long id) {
        CustomPatchMit customPatchMit = CustomPatchMit.findWhere(id: id)
        respond customPatchMit
    }

    @Transactional
    def save(CustomPatchMit customPatchMit) {
        if (customPatchMit == null) {
            render "status: NOT_FOUND"
            return
        }
        try {
            VulnerabilityDetail vulnDetail = customPatchMit.vulnerabilityDetail
            vulnDetail.suspense = "three"
            vulnDetail.save()
            customPatchMit.save()
        } catch (ValidationException e) {
            log.error (e.getMessage())
            respond customPatchMit.errors
            return
        }
        respond customPatchMit, [status: CREATED]
    }

    @Transactional
    def update(CustomPatchMit customPatchMit) {
        if (customPatchMit == null) {
            render "status: NOT_FOUND"
            return
        }
        try {
            if (customPatchMit.approved) {
                customPatchMit.vulnerabilityDetail.suspense = "one"
            }
            else {
                customPatchMit.vulnerabilityDetail.suspense = "three"
            }
            customPatchMit.save()
        } catch (ValidationException e) {
            log.error (e.getMessage())
            respond customPatchMit.errors
            return
        }
        respond customPatchMit, [status: CREATED]
    }

    @Transactional
    def delete(Long id) {
        CustomPatchMit customPatchMit = CustomPatchMit.findWhere(id: id)
        VulnerabilityDetail vulnerabilityDetail = customPatchMit.vulnerabilityDetail
        customPatchMit.delete(flush:true)
        Mitigation mitigation = Mitigation.findWhere(vulnerability: vulnerabilityDetail.vulnerability, aor: customPatchMit.vulnerabilityDetail.asset.aor)
        if (!mitigation) {
            String suspense = vulnerabilityService.setSuspense1(vulnerabilityDetail)
            vulnerabilityDetail.suspense = suspense
            vulnerabilityDetail.save()
        }
        render "status: NO_CONTENT"
    }

    def getCustomPatchMit(){
        String idString = params.id.toString()
        respond (mitigationService.getCustomPatchMit(idString))
    }

    def getCustomPatchMit1() {
        String customPatchMitIdString = params.customPatchMitId.toString()
        respond (mitigationService.getCustomPatchMit1( customPatchMitIdString))
    }

    def getCustomPatchMits() {
        respond (mitigationService.getCustomPatchMits())
    }

    @Transactional
    def setCustomPatchMit() {
        def valuesReturned = request.JSON
        mitigationService.setCustomPatchMit(valuesReturned)
        respond "Complete"
    }
}
