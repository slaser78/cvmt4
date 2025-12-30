package jten.mil

class CustomStigMit {
    String name = "customStigMit_" + System.currentTimeMillis()
    String resourcesRequired
    Date completeDate
    Date createDate = new Date()
    String milestone
    String cyberComment
    String milestoneChange
    String mitComment
    Boolean approved = false
    String status = "Created"
    String submitComment
    String mitType
    static belongsTo= [assetStigVulnStatus:AssetStigVulnStatus]
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