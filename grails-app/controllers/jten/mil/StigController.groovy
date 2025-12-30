package jten.mil

import grails.gorm.transactions.ReadOnly
import grails.gorm.transactions.Transactional
import grails.validation.ValidationException
import static org.springframework.http.HttpStatus.*

@Transactional
class StigController {
    StigService stigService

    @ReadOnly
    def index() {
        respond Stig.list()
    }

    def save(Stig stig) {
        if (stig == null) {
            render "status: NOT_FOUND"
            return
        }
        try {
            stig.save()
        } catch (ValidationException e) {
            e.suppressed
            respond stig.errors, view: 'create'
            return
        }
        respond stig, [status: CREATED, view: "show"]
    }

    def update(Stig stig) {
        if (stig == null) {
            render "status: NOT_FOUND"
            return
        }
        try {
            stig.save()
        } catch (ValidationException e) {
            e.suppressed
            respond stig.errors, view: 'edit'
            return
        }
        respond stig, [status: OK, view: "show"]
    }

    def delete(Long id) {
        if (id == null) {
            render "status: NOT_FOUND"
            return
        }
        stigService.deleteStigEntry(id)
        render "status: NO_CONTENT"
    }

    def uploadStig() {
        log.warn ("Start Upload of STIG Template Data")
        def file = request.getFile('file')
        byte[] fileByte = file.getBytes()
        String stigId = request.getParameter('stigId')
        Long stigLong = Long.valueOf(stigId)
        Stig stigValue = Stig.findWhere(id: stigLong)
        if (file.empty) {
            log.warn("File empty.")
        } else {
            try {
                stigService.updateStig(fileByte, stigValue)
            } catch (ValidationException e) {
                e.suppressed
            }
        }
        log.warn ("Finish Upload of STIG Template Data")
        respond stigValue
    }

    @ReadOnly
    def assetChecklist() {
        Long longId = params.long('asset')
        Asset asset = Asset.get(longId)
        if (!asset) {
            return
        }

        String xmlFile = stigService.exportAssetStig(asset)
        byte[] bytes = xmlFile.getBytes('UTF-8')
        response.contentType = 'application/octet-stream'
        response.characterEncoding = 'UTF-8'
        response.setHeader('Content-Disposition', "attachment; filename=\"${asset.name}.ckl\"")
        response.setContentLength(bytes.length)
        response.outputStream.withCloseable { os ->
            os.write(bytes)
            os.flush()
        }
    }

    def updateTemplate() {
        log.warn ("Start Update of Template Data")
        String paramsString = params
        def paramsList = paramsString.split(":")
        def fileName = paramsList[0]
        def fileName1 = fileName.replaceAll("\\[","")
        def file = request.getFile(fileName1)
        def baseDir = (grailsApplication.config.getProperty('baseDir', String.class))
        def filePath = "${baseDir}data.zip"
        new File(filePath).withOutputStream {out ->
            def dataOut = new DataOutputStream(out)
            def content = file.getBytes()
            dataOut.write(content)
        }
        if (file.empty) {
            log.warn("File empty.")
        } else {
            try {
                stigService.updateTemplate(fileName1)
            } catch (ValidationException e) {
                e.suppressed
            }
        }
        log.warn ("Finish Update of STIG Template Data")
        render "status: Complete"
    }
}