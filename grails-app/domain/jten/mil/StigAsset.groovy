package jten.mil

class StigAsset {
    boolean complete = false
    Stig stig
    Asset asset
    static belongsTo = [asset: Asset]
    static constraints = {
    }
}