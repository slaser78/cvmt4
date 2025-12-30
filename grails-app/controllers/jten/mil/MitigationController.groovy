package jten.mil

import grails.gorm.transactions.ReadOnly
import grails.gorm.transactions.Transactional
import grails.validation.ValidationException
import static org.springframework.http.HttpStatus.*

@ReadOnly
class MitigationController {
    def mitigationService
    def vulnerabilityService

    @Transactional
    def save(Mitigation mitigation) {
        if (mitigation == null) {
            render "status: NOT_FOUND"
            return
        }
        try {
            Aor aor = mitigation.aor
            Vulnerability vulnerability = mitigation.vulnerability
            List <Asset> assets = Asset.findAllWhere(aor: aor)
            for (asset in assets) {
                VulnerabilityDetail vulnDetail = VulnerabilityDetail.findWhere(vulnerability: vulnerability, asset: asset)
                if (vulnDetail) {
                    vulnDetail.suspense = "one"
                    vulnDetail.save()
                }
                mitigation.save()
            }
        } catch (ValidationException e) {
            e.suppressed
            respond mitigation.errors
            return
        }
        respond mitigation, [status: OK]
    }

    @Transactional
    def update(Mitigation mitigation) {
        if (mitigation == null) {
            render "status: NOT_FOUND"
            return
        }
        try {
            List <Asset> assets = Asset.findAllWhere(aor: mitigation.aor)
            for (asset in assets) {
                List<VulnerabilityDetail> vulnerabilityDetails = VulnerabilityDetail.findAllWhere(vulnerability: mitigation.vulnerability, asset: asset)
                if (vulnerabilityDetails) {
                    for (vulnerabilityDetail in vulnerabilityDetails) {
                        vulnerabilityDetail.suspense = vulnerabilityService.setSuspense1(vulnerabilityDetail)
                        vulnerabilityDetail.save()
                    }
                }
            }
            mitigation.save(flush: true)
        } catch (ValidationException e) {
            e.suppressed
            respond mitigation.errors, view:'edit'
            return
        }
        respond mitigation, [status: OK]
    }

    @Transactional
    def delete(Long id) {
        if (id == null) {
            render "status: NOT_FOUND"
            return
        }
        Mitigation mitigation = Mitigation.findWhere(id: id)
        Aor aor = mitigation.aor
        List<Asset> assets = Asset.findAllWhere (aor: aor)
        Vulnerability vulnerability = mitigation.vulnerability
        for (asset in assets) {
            VulnerabilityDetail vulnDetail = VulnerabilityDetail.findWhere(vulnerability: vulnerability, asset: asset)
            if (vulnDetail){
                if (!vulnDetail.customPatchMit) {
                    String suspense = vulnerabilityService.setSuspense2(vulnDetail)
                    vulnDetail.suspense = suspense
                    vulnDetail.save()
                }
            }
        }
        mitigation.delete()
        render "status: NO_CONTENT"
    }

    def getPatchMit() {
        String vulnDetailIdString = params.vulnDetailId.toString()
        respond (mitigationService.getPatchMit( vulnDetailIdString))
    }

    def getPatchMit1() {
        String patchMitIdString = params.patchMitId.toString()
        respond (mitigationService.getPatchMit1( patchMitIdString))
    }

    def getPatchMits() {
        respond(mitigationService.getPatchMits())
    }

    @Transactional
    def deleteMit() {
        log.warn ("Start Mitigation Deletions")
        respond (mitigationService.delMit())
        log.warn ("Finish Mitigation Deletions")
    }
}