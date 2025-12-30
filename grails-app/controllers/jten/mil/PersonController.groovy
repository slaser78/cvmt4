package jten.mil

import grails.gorm.transactions.Transactional
import grails.rest.RestfulController
import grails.validation.ValidationException
import static org.springframework.http.HttpStatus.*
import grails.gorm.transactions.ReadOnly

class PersonController extends RestfulController<Person> {
    def userService

    PersonController() {
        super(Person)
    }

    @ReadOnly
    def index() {
        respond Person.list()
    }

    @Transactional
    def save(Person person) {
        try {
            person.save()
            PersonRole.create(person, Role.findWhere(authority: person.authority),true)
        } catch (ValidationException e) {
            e.suppressed
            respond person.errors
            return
        }
        respond person, [status: CREATED]
    }

    @Transactional
    def update(Person person) {
        try {
            person.save()
            PersonRole.where{person == person}.deleteAll()
            Role role = Role.findWhere(authority: params.role)
            PersonRole.create(person, role, true)
        } catch (ValidationException e) {
            e.suppressed
            respond person.errors
            return
        }
        respond person, [status: CREATED]
    }

    @Transactional
    def delete(Long id) {
        if (id == null) {
            render "NOT_FOUND"
            return
        }
        Person personInstance = Person.findWhere(id: id)
        PersonRole.where{person == personInstance}.deleteAll()
        personInstance.delete()
        render "NO_CONTENT"
    }

    @Transactional
    def usernameGetInitial () {
        Enumeration headerNames = request.getHeaderNames()
        String user = "scott"  //change for production
        while (headerNames.hasMoreElements()) {
            String key = (String) headerNames.nextElement()
            if (key == "oidc_claim_email") {
                user = request.getHeader(key)
            }
        }
        log.warn ("User: " + user)
        def personValue = Person.findWhere(username: user)
        if (personValue) {
            LinkedHashMap<String, String> personMap = ["username": user]
            LinkedHashMap<String, String> aorMap = ["aor": personValue.aor.name]
            LinkedHashMap<String, String> pocMap = ["poc": personValue.poc.name]
            LinkedHashMap<String, String> roleMap = ["role": personValue.authorities.authority[0]]
            personValue.lastLogonDate = new Date()
            personValue.save()
            def initialValues = personMap + aorMap + pocMap + roleMap
            respond(initialValues)
        } else {
            log.error ("No user name found in CVMT for user ${user}")
            redirect (url: "https://sso-dev.jten.mil")
        }
    }

    @Transactional
    def updatePerson () {
        def person = request.JSON
        userService.updatePerson(person)
        respond "Complete"
    }

    @Transactional
    def setPerson() {
        def person =  request.JSON
        println "Person: " + person
        Person person1 = userService.setUser(person)
        respond person1, [status: CREATED]
    }
}