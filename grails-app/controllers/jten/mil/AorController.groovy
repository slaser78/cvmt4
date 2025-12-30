package jten.mil

import grails.gorm.transactions.Transactional
import grails.validation.ValidationException
import static org.springframework.http.HttpStatus.*

@Transactional
class AorController {

    def index() {
        respond Aor.list().toSorted {a,b -> a.name<=> b.name}
    }

    def save(Aor aor) {
        if (aor == null) {
            render "status: NOT_FOUND"
            return
        }
        try {
            aor.save()
        } catch (ValidationException e) {
            e.suppressed
            respond aor.errors
            return
        }
        respond aor
    }

    def update(Aor aor) {
        if (aor == null) {
            render "status: NOT_FOUND"
            return
        }
        try {
            aor.save()
        } catch (ValidationException e) {
            e.suppressed
            respond aor.errors, view:'edit'
            return
        }
        respond aor, [status: OK]
    }

    def delete(Long id) {
        if (id == null) {
            render "status: NOT_FOUND"
            return
        }
        Aor aor = Aor.findWhere(id:id)
        aor.delete()
        render "status: NO_CONTENT"
    }
}