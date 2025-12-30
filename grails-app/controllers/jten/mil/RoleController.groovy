package jten.mil


import grails.validation.ValidationException
import static org.springframework.http.HttpStatus.*

class RoleController {

    def index() {
        respond Role.list()
    }

    def save(Role role) {
        if (role == null) {
            render "status: NOT_FOUND"
            return
        }
        try {
            role.save()
        } catch (ValidationException e) {
            e.suppressed
            respond role.errors, view:'create'
            return
        }
        respond role, [status: CREATED, view:"show"]
    }

    def update(Role role) {
        if (role == null) {
            render "status: NOT_FOUND"
            return
        }
        try {
            role.save()
        } catch (ValidationException e) {
            e.suppressed
            respond role.errors, view:'edit'
            return
        }
        respond role, [status: OK, view:"show"]
    }

    def delete(Long id) {
        if (id == null) {
            render "status: NOT_FOUND"
            return
        }
        Role role = Role.findWhere(id: id)
        role.delete()
        render "status: NO_CONTENT"
    }
}