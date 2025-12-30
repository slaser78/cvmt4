package jten.mil

class Ips {

    static belongsTo= [asset:Asset]
    String ipAddress
    String description

    String toString() {
        ipAddress
    }
}