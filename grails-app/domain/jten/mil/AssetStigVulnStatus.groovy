package jten.mil

class AssetStigVulnStatus {
    String status
    String comment
    boolean reviewed = false
    StigAsset stigAsset
    StigVulnerability stigVulnerability
    static belongsTo = [asset: Asset]
    Date firstSeen = new Date()
    static hasOne = [customStigMit:CustomStigMit]

    static constraints = {
        comment nullable:true, maxSize:50000
        customStigMit nullable:true
    }
}