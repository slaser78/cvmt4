package jten.mil

import groovy.transform.EqualsAndHashCode
import groovy.transform.ToString
import grails.compiler.GrailsCompileStatic

@GrailsCompileStatic
@EqualsAndHashCode(includes='username')
@ToString(includes='username', includeNames=true, includePackage=false)
class Person implements Serializable {
    private static final long serialVersionUID = 1
    String username
    Date lastLogonDate = new Date()
    Aor aor
    Poc poc

    Set<Role> getAuthorities() {
        (PersonRole.findAllByPerson(this) as List<PersonRole>)*.role as Set<Role>
    }

    static constraints = {
        username nullable: false, blank: false, unique: true
        poc nullable: true
        aor nullable: true
        lastLogonDate nullable:true
    }

    String toString() {
        username
    }
}
