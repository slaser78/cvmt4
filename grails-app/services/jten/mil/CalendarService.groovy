package jten.mil

import grails.gorm.transactions.Transactional
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.time.ZoneId

class CalendarService {

    @Transactional
    def importCalendar(def fileData) {
        String file = new String(fileData, "UTF-8")
        def data = file.readLines()*.split(',')
        def total = []
        for (line in data) {
            String entry = line.entry
            String dueDate = line.dueDate
            String priority = line.priority
            String ipAddress = line.ipAddress
            def lineMap = ["entry": entry, "dueDate": dueDate, "priority": priority, "ipAddress": ipAddress]
            total += lineMap
        }
        def response = JsonOutput.toJson(total)
        def slurper = new JsonSlurper()
        //Parse calendar list into JSON
        def calendarList = slurper.parseText(response)
        //For each calendar entry in the list
        for (def item : calendarList) {
            try {
                String entry = item.entry
                String ipAddress = item.ipAddress
                def assetInstance = Asset.findWhere(ipAddress: ipAddress)
                if (assetInstance) {
                    String priority = item.priority
                    String dueDate = item.dueDate
                    def formatter = DateTimeFormatter.ofPattern("MM/dd/yyyy")
                    LocalDate localDate = LocalDate.parse(dueDate, formatter)
                    Date dueDate1 = Date.from(
                            localDate.atStartOfDay(ZoneId.systemDefault()).toInstant()
                    )
                    log.info("Imported calendar entry: ${entry} for asset: ${assetInstance.name}")
                    try {
                        def calendarInstance = new jten.mil.Calendar(entry: entry, priority: priority, dueDate: dueDate1,
                                asset: assetInstance)
                        calendarInstance.save(flush: true)
                    }
                    catch(e){
                        e.stackTrace
                    }
                }
                else {
                    log.error ("Calendar entry: ${entry} failed with no asset with IP address: ${ipAddress} found")
                }
            }
            catch (Exception e){
                e.stackTrace
            }
        }
    }

    def calendarList() {
        def calendarList = java.util.Calendar.list()
        def calendarList1 =[]
        for (calendar in calendarList) {
            def calendarEntry = [
                    "id"       : calendar.id,
                    "dueDate"  : calendar.dueDate,
                    "assetName": calendar.asset.name,
                    "entry"    : calendar.entry,
                    "aor"      : calendar.asset.aor.name,
                    "poc"      : calendar.asset.poc.name,
                    "priority" : calendar.priority
            ]
            calendarList1 += calendarEntry
        }
        return calendarList1
    }
}
