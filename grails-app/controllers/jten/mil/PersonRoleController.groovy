package jten.mil

import grails.gorm.transactions.ReadOnly
import grails.gorm.transactions.Transactional
import grails.validation.ValidationException

@ReadOnly
class PersonRoleController {
    def index(Integer max) {
        params.max = Math.min(max ?: 10, 100)
        respond PersonRole.list(params), model:[personRoleCount: PersonRole.count()]
    }

    def show(PersonRole personRole) {
        respond personRole
    }

    def create() {
        respond new PersonRole(params)
    }
    @Transactional
    def save(PersonRole personRole) {
        if (personRole == null) {
            return
        }

        try {
            personRole.save()
            redirect personRole
        }
        catch (ValidationException e) {
            e.suppressed
            respond personRole.errors, view:'create'
        }
    }

    def edit(PersonRole personRole) {
        respond personRole
    }

    @Transactional
    def update(PersonRole personRole) {
        try {
            personRole.save()
            redirect personRole
        } catch (ValidationException e) {
            e.suppressed
            respond personRole.errors, view:'edit'
        }
    }
    @Transactional
    def delete(PersonRole personRole) {
        personRole.delete()
        redirect action:"index", method:"GET"
    }
}