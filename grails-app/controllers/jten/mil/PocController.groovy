package jten.mil

import grails.validation.ValidationException
import static org.springframework.http.HttpStatus.*

class PocController {

    def index() {
        respond Poc.list().toSorted {a,b -> a.name<=> b.name}
    }

    def save(Poc poc) {
        if (poc == null) {
            render "status: NOT_FOUND"
            return
        }
        try {
            poc.save()
        } catch (ValidationException e) {
            e.suppressed
            respond poc.errors, view:'create'
            return
        }
        respond poc, [status: CREATED, view:"show"]
    }

    def update(Poc poc) {
        if (poc == null) {
            render "status: NOT_FOUND"
            return
        }
        try {
            poc.save()
        } catch (ValidationException e) {
            e.suppressed
            respond poc.errors, view:'edit'
            return
        }
        respond poc, [status: OK, view:"show"]
    }

    def delete(Long id) {
        if (id == null) {
            render "status: NOT_FOUND"
            return
        }
        Poc poc = Poc.findWhere(id: id)
        poc.delete()
        render "status: NO_CONTENT"
    }
}