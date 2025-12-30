package jten.mil

class MitigationStig {
    String name = "Mit_" + System.currentTimeMillis()
    StigVulnerability stigVulnerability
    String resourcesRequired
    Date completeDate
    Date createDate = new Date()
    String milestone
    String cyberComment
    String milestoneChange
    String mitComment
    Aor aor
    Poc poc
    Boolean approved = false
    String status = "Created"
    String submitComment
    String mitType

    static constraints = {
        resourcesRequired nullable:true,  maxSize: 5000
        milestone nullable:true,  maxSize: 5000
        cyberComment nullable:true, maxSize: 5000
        milestoneChange nullable:true,  maxSize: 5000
        mitComment nullable:true, maxSize: 5000
        submitComment nullable:true,  maxSize: 5000

    }
    String toString() {
        name
    }
}