package jten.mil

import grails.gorm.transactions.Transactional
import grails.validation.ValidationException
import static org.springframework.http.HttpStatus.*

class CalendarController {
    def calendarService

    @Transactional
    def save(Calendar calendar) {
        if (calendar == null) {
            render "status: NOT_FOUND"
            return
        }
        try {
            calendar.save()
        } catch (ValidationException e) {
            e.suppressed
            respond calendar.errors, view:'create'
            return
        }
        respond calendar, [status: CREATED, view:"show"]
    }
    @Transactional
    def update(Calendar calendar) {
        if (calendar == null) {
            render "status: NOT_FOUND"
            return
        }
        try {
            calendar.save()
        } catch (ValidationException e) {
            e.suppressed
            respond calendar.errors, view:'edit'
        }
        respond calendar, [status: OK, view:"show"]
    }
    @Transactional
    def delete(Long id) {
        if (id == null) {
            render "status: NOT_FOUND"
            return
        }
        Calendar calendar = Calendar.findWhere(id: id)
        calendar.delete()
        render "status: NO_CONTENT"
    }

    def calendarEntries() {
        def calendarList = calendarService.calendarList()
        respond calendarList
    }

    def importCalendar () {
        def file = request.getFile('file')
        if(file.empty){
            log.warn( "File empty.")
        }
        else {
            try {
                calendarService.importCalendar(file.getBytes())
            }  catch (ValidationException e) {
                e.suppressed
            }
        }
    }
}