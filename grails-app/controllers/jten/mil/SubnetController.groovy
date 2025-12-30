package jten.mil

import grails.validation.ValidationException
import static org.springframework.http.HttpStatus.CREATED
import static org.springframework.http.HttpStatus.OK
import grails.gorm.transactions.ReadOnly
import grails.gorm.transactions.Transactional

@ReadOnly
class SubnetController {
    def assetService

    def index() {
        respond Subnet.list()
    }

    def show(Long id) {
        Subnet subnet = Subnet.get(id)
        respond subnet
    }

    @Transactional
    def save(Subnet subnet) {
        if (subnet == null) {
            render "status: NOT_FOUND"
            return
        }
        try {
            subnet.save()
        } catch (ValidationException e) {
            e.suppressed
            respond subnet.errors
            return
        }
        respond subnet, [status: CREATED, view:"show"]
    }

    @Transactional
    def update(Subnet subnet) {
        if (subnet == null) {
            render "status: NOT_FOUND"
            return
        }
        try {
            subnet.save()
        } catch (ValidationException e) {
            log.error (e.getMessage())
            respond subnet.errors
            return
        }
        respond subnet, [status: OK, view:"show"]
    }

    @Transactional
    def delete(Long id) {
        Subnet subnet = Subnet.get(id)
        if (id == null || subnet.delete() == null) {
            render "status: NOT_FOUND"
            return
        }
        render "status: NO_CONTENT"
    }

    @Transactional
    def setSubnet() {
        log.warn ("Start set subnets")
        assetService.setSubnets()
        log.warn ("Finish set subnets")
        respond "Complete"
    }
}