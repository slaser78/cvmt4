package jten.mil

class Asset {
    String name
    static hasMany = [calendar:Calendar,
                      ips:Ips,
                      vulnerabilityDetail:VulnerabilityDetail,
                      stigAsset:StigAsset]
    String ipAddress
    String score
    String description
    Poc poc
    Aor aor
    String comment
    Boolean swDetail = false
    String role
    String assetType = "Computing"
    String macAddress
    String techArea
    Boolean webOrDatabase = false
    String webOrDatabaseSite
    String webOrDatabaseInstance
    Subnet subnet
    Date lastScan
    Boolean posture = false
    Boolean credentialedScan = false
    String opSystem
    String deviceType
    Boolean autoMit = false
    Boolean crit = false
    Boolean por = false

    static constraints = {
        name unique:true
        calendar nullable: true
        ips nullable: true
        stigAsset nullable: true
        vulnerabilityDetail nullable: true
        score nullable: true
        description nullable: true
        comment nullable:true
        role nullable:true
        macAddress nullable:true
        techArea nullable:true
        webOrDatabaseSite nullable:true
        webOrDatabaseInstance nullable:true
        subnet nullable: true
        lastScan nullable:true
        opSystem nullable:true, maxSize:3000
        deviceType nullable:true
    }

    String toString() {
        name
    }
}