package jten.mil

import grails.gorm.transactions.Transactional
import grails.validation.ValidationException
import static org.springframework.http.HttpStatus.*

class IpsController {

    def index() {
        respond Ips.list()
    }
    @Transactional
    def save(Ips ips) {
        if (ips == null) {
            render "status: NOT_FOUND"
            return
        }
        try {
            ips.save()
        } catch (ValidationException e) {
            e.suppressed
            respond ips.errors, view:'create'
            return
        }
        respond ips, [status: CREATED, view:"show"]
    }
    @Transactional
    def update(Ips ips) {
        if (ips == null) {
            render "status: NOT_FOUND"
            return
        }
        try {
            ips.save()
        } catch (ValidationException e) {
            e.suppressed
            respond ips.errors, view:'edit'
            return
        }
        respond ips, [status: OK, view:"show"]
    }
    @Transactional
    def delete(Long id) {
        if (id == null) {
            render "status: NOT_FOUND"
            return
        }
        Ips ips = Ips.findWhere(id: id)
        ips.delete()
        render "status: NO_CONTENT"
    }
}
