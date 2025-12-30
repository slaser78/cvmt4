package jten.mil

class Stig {

    String assetType
    String version1
    String title
    String description
    String classification
    int stigCount = 0
    String targetKey
    String customName
    String stigId
    String fileName
    String releaseInfo
    String notice
    String source
    String benchmarkName
    String applications
    String uuid
    String tenable

    static mapping = {
        sort "title"
    }

    static constraints = {
        assetType nullable:true
        version1 nullable:true
        title unique: true
        description nullable: true, maxSize:5000
        classification nullable: true
        targetKey nullable: true
        customName nullable:true
        stigId nullable:true
        fileName nullable:true
        releaseInfo nullable:true
        notice nullable:true
        source nullable:true
        benchmarkName nullable:true
        applications nullable:true
        uuid nullable: true
        tenable nullable: true
    }
    String toString() {
        title
    }
}