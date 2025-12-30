package jten.mil

class Calendar {
    String entry
    String priority
    Date dueDate
    static belongsTo= [asset:Asset]
    static constraints = {
    }
    String toString() {
        entry
    }
}