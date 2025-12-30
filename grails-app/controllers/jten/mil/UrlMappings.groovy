package jten.mil

class UrlMappings {
    static mappings = {
        delete "/$controller/$id(.$format)?"(action:"delete")
        get "/$controller(.$format)?"(action:"index")
        get "/$controller/$id(.$format)?"(action:"show")
        post "/$controller(.$format)?"(action:"save")
        put "/$controller/$id(.$format)?"(action:"update")
        patch "/$controller/$id(.$format)?"(action:"patch")

        "/"(controller: 'application', action:'index')
        "500"(view: '/error')
        "404"(view: '/notFound')
        "/login/auth"(controller: "login", action: "auth")

        //Asset
        //Upload list of assets to be deleted
        //Activated by Maintenance "Bulk Asset Delete" button
        "/deleteBulkAsset" (controller: 'asset', action:'deleteBulkAsset')

        //Starts service to retrieve asset list from ACAS
        //Activated by Maintenance "Get Assets" button
        "/getAssets" (controller: 'asset', action:'getAssets')

        //Get ACAS last patch scan details info for all assets
        //Activated by Maintenance "AssetScanDetail" button
        "/getAssetScanDetails1" (controller: 'asset', action:'getAssetScanDetails1')

        //Updates from ACAS asset operating system information
        //Activated by Maintenance "GetOperatingSystems" button
        "/getOpSystems" (controller: 'asset', action:'getOpSystems')

        //Updated score of asset
        //Activated by Maintenance, "Get Score" button
        "/getScore" (controller: 'asset', action:'getScore')

        //Performs DNS lookup of asset-IP address information from Infoblox
        //Removes assets with no DNS A or Host Records (unless there are associated STIGs)
        //Activated by Maintenance "Lookup" Button
        "/lookupAsset" (controller: 'asset', action:'lookupAsset')

        //Get VulnDetail Details for all Assets
        //Activated by Maintenance "Scan Details" button
        "/getScanDetails" (controller: 'asset', action:'getScanDetails')

        //Manually upload asset information in .csv format
        //Activated by Maintenance "Import Asset" button
        "/uploadAsset" (controller: 'asset', action:'uploadAsset')

        //Get Asset DNS values from Infoblox
        //Activated by Asset View, "DNS"
        "/getAssetDns" (controller: 'asset', action:'getAssetDns')
        "/checkAcas" (controller: 'asset', action: 'checkAcas')

        //AssetStigVulnStatus

        //Allows multiple STIG Vulnerability entries to have their "Reviewed" field to be set
        //Activated by stigAsset/stigVuln/EditStigVuln form
        "/setAssetStigVulnStatusEntry" (controller: 'assetStigVulnStatus', action: 'setAssetStigVulnStatusEntry')

        //Gets all StigAssetVulnerability entries
        //Activated by Stig Asset Vulnerability Table opening
        "/getAssetStigVulnStatusEntries" (controller: 'assetStigVulnStatus', action: 'getAssetStigVulnStatusEntries')

        //Gets STIG Vulnerabilities for an asset
        //Activated by the STIG Vulnerability Table opening
        "/getAssetStigVulnStatuses" (controller: 'assetStigVulnStatus', action: 'getAssetStigVulnStatuses')

        //Get AssetStigVulnStatus entry to be used for creating a custom STIG mitigation
        //Activated by the Custom Mitigation Table, Add Custom Mitigation form
        "/getAssetStigVulnStatus" (controller: 'assetStigVulnStatus', action: 'getAssetStigVulnStatus')

        //Sets all AssetStigVulnerabilityStatus "Reviewed" fields to false
        //Activated by Maintenance "Set ASVS False" button
        "/setAsvsFalse" (controller: 'assetStigVulnStatus', action: 'setAsvsFalse')

        //Get AssetStigVulnerabilities Count
        //Activated by accessing StigVulnTable
        "/getAsvsCount" (controller: 'assetStigVulnStatus', action: 'getAsvsCount')

        //Imports Asset SCAP benchmark information from .ckl file
        //Activated by STIG Asset Table, "Import SCAP" button (for one asset)
        "/importScap" (controller: 'assetStigVulnStatus', action: 'importScap')

        //Get STIG Vulnerability Details
        //Activated by STIG Vulnerability Table
        "/getStigVulnDetail" (controller: 'assetStigVulnStatus', action: 'getStigVulnDetail')

        //Audit
        //Get audit update information
        //Activated by the Asset Table "Get Audit Results" button
        "/getAuditResults" (controller: 'asset', action:'getAuditResults')

        //Get audit update information for one asset
        //Activated by the Asset Table "Get Audit Update" button
        "/getAuditUpdate" (controller: 'asset', action:'getAuditUpdate')

        //Calendar
        //Retrieve calendar entry info for Calendar View
        "/calendarEntries" (controller: 'calendar', action: 'calendarEntries')

        //Allows bulk upload of Calendar information
        //Activated by Maintenance "Import Calendar" button
        "/importCalendar" (controller: 'calendar', action: 'importCalendar')

        //Custom Patch Mitigation

        //Get Custom Patch Mitigation info for one asset (when Custom Patch Mitigation info the asset exists)
        //Activated by "Patch Vulnerability" table, "Custom Mitigation" button
        "/getCustomPatchMit" (controller: 'customPatchMit', action: 'getCustomPatchMit')

        //Get Patch Mitigation info for one asset (when Patch Mitigation info for the asset exists)
        //Activated by "AOR Patch Mitigation" table, "Edit Patch Mitigation" button
        "/getCustomPatchMit1" (controller: 'customPatchMit', action: 'getCustomPatchMit1')

        //Get Custom Patch Mitigation information
        //Activated by opening Custom Patch Mitigation Table
        "/getCustomPatchMits" (controller: 'customPatchMit', action: 'getCustomPatchMits')

        //Set Custom Patch Mitigation info for one asset
        //Activated by "Patch Vulnerability" table, "Custom Mitigation" button
        "/setCustomPatchMit" (controller: 'customPatchMit', action: 'setCustomPatchMit')

        //Custom STIG Mitigation
        //Get Custom STIG Mitigation info for one asset (when Custom Patch Mitigation info the asset exists)
        //Activated by "Patch Vulnerability" table, "Custom Mitigation" button
        "/getCustomStigMit" (controller: 'customStigMit', action: 'getCustomStigMit')

        //Get Custom STIG Mitigation information
        //Activated by opening Custom Patch Mitigation Table
        "/getCustomStigMits" (controller: 'customStigMit', action: 'getCustomStigMits')

        //Set Custom STIG Mitigation info for one asset
        //Activated by "Patch Vulnerability" table, "Custom Mitigation" button
        "/setCustomStigMit" (controller: 'customStigMit', action: 'setCustomStigMit')

        //Elastic
        // Upload Patch Vulnerability Info to Elastic
        //Activated by Maintenance, "Patch" button
        "/elasticPatchUpload" (controller: 'asset', action:'elasticPatchUpload')

        // Upload STIG Vulnerability Info to Elastic
        //Activated by Maintenance, "STIG" button
        "/elasticStigUpload" (controller: 'asset', action:'elasticStigUpload')

        // Upload Asset Info to Elastic
        //Activated by Maintenance, "Asset" button
        "/elasticAssetUpload" (controller: 'asset', action:'elasticAssetUpload')

        // Upload Device Types Compliance Info to Elastic
        //Activated by Maintenance, "Device Types" button
        "/elasticDeviceTypesUpload" (controller: 'asset', action:'elasticDeviceTypesUpload')

        //Mitigation

        //Get Patch Mitigation info for one asset (when Patch Mitigation info for the asset exists)
        //Activated by "Patch Vulnerability" table, "Mitigation" button
        "/getPatchMit" (controller: 'mitigation', action: 'getPatchMit')

        //Get Patch Mitigation info for one asset (when Patch Mitigation info for the asset exists)
        //Activated by "AOR Patch Mitigation" table, "Edit Patch Mitigation" button
        "/getPatchMit1" (controller: 'mitigation', action: 'getPatchMit1')

        //Get Custom Patch Mitigation information
        //Activated by opening Patch Mitigation Table
        "/getPatchMits" (controller: 'mitigation', action: 'getPatchMits')

        //Delete Mitigation entry
        //Activated by Patch Mitigation Table, Delete button
        "/deleteMit" (controller: 'mitigation',  action: 'deleteMit')

        //MitigationStig

        //Get STIG Mitigation info for one asset (when STIG Mitigation info the asset exists)
        //Activated by "STIG Vulnerability" table, "Mitigation" button
        "/getStigMit" (controller: 'mitigationStig', action: 'getStigMit')

        //Get STIG Mitigation information
        //Activated when opening STIG Mitigation Table
        "/getStigMits" (controller: 'mitigationStig', action: 'getStigMits')

        //Neo4j
        //Uploads Patch Vulnerabilty info to Neo4J database
        //Activated by Maintenance, "Update Neo4J" button
        "/updateNeo4j" (controller: 'asset', action: 'updateNeo4j')

        //Person
        //Verifies user is found in CVMT Person table.  Uses "oidc_claim_email" from Keycloak header.
        //Activated by the initial login to CVMT.  Returns aor, poc, username, and role values
        "/usernameGetInitial" (controller: 'person', action: 'usernameGetInitial')

        //Updates Name, Role, POC, and AOR fields
        //Activated from PersonTable.
        "/updatePerson" (controller: 'person', action: 'updatePerson')

        //Add new persons to CVMT Person Table
        //Activated by Person Table, "Add Person" form
        "/setPerson" (controller: 'person', action: 'setPerson')

        //Stig
        //Upload New STIG template
        //Activated from template table, "Upload STIG" button
        "/uploadStig" (controller: 'stig', action:'uploadStig')

        //Upload STIG Templates from DISA in form of a zip file
        //Activated from maintenance page, "Upload Templates"
        "/updateTemplate" (controller: 'stig', action: 'updateTemplate')

        //StigAsset
        //Export Stig Asset Checklists in Zip file
        //Activated from STIG Asset, "Export Checkist" button
        "/exportSAChecklist" (controller: 'stigAsset', action: 'exportSAChecklist')

        //Checks all STIG Asset vulnerabilities to determine if they are all reviewed
        //Activated when closing STIG Asset Vulnerability Table
        "/getStigAssetComplete" (controller: 'stigAsset', action: 'getStigAssetComplete')

        //Get STIG Asset entries
        //Activated when opening STIG Asset Table
        "/getStigAssets" (controller: 'stigAsset' , action:'getStigAssets')

        //Get asset postures from ACAS
        //Activated from Maintenance, "Get Postures" button
        "/getPosture" (controller: 'stigAsset', action: 'getPosture')

        //Get asset postures from ACAS for one asset
        //Activated from Asset Table, "Get Posture Update"
        "/getPosture1" (controller: 'stigAsset', action: 'getPosture1')

        //StigVulnerability
        //Get STIG Template Vulnerabilities
        //Activated by Stig Template Vulnerability Table
        "/getStigVuln" (controller: 'stigVulnerability', action: 'getStigVuln')

        //Get StigVulnerability to create Mitigation Strategy
        //Activated by Vulnerability/STIG, "Add Mit" Form
        "/getStigVuln2" (controller: 'stigVulnerability', action:'getStigVuln2')

        //Subnet
        //Set subnet info for each asset
        //Activated by Maintenance "Set Subnet" button
        "/setSubnet" (controller: 'subnet', action: 'setSubnet')

        //Vulnerability

        //Get Asset Patch vulnerabilities from ACAS
        //Activated by Maintenance, "Get Asset Vulnerabilities" button
        "/getAssetPatchVulns" (controller: 'vulnerability', action: 'getAssetPatchVulns')

        //Get Patch Vulnerabilities from ACAS
        //Activated by Maintenance, "Get Asset Scan Details" button
        "/getPatchUpdate" (controller: 'vulnerability', action: 'getPatchUpdate')

        //Get Patch Vulnerabilities entries
        //Activated when opening Patch Vulnerability table
        "/getPatchVulns" (controller: 'vulnerability', action: 'getPatchVulns')

        //Get Patch Vulnerability Data
        //Activated when opening Patch Vulnerability Table
        "/getPatchVulns1" (controller: 'vulnerability', action: 'getPatchVulns1')

        //Get Patch Vulnerability Detail for one asset-patch
        //Activated when opening Custom Patch Mit table
        "/getPatchVulnDetail" (controller: 'vulnerability', action: 'getPatchVulnDetail')

        //Get Patch Vulnerability details
        //Activated by Patch Vulnerability Table, "Detail" button
        "/getPatchVulnDetail1" (controller: 'vulnerability', action: 'getPatchVulnDetail1')

        //Runs new Patch Scan using ACAS
        //Activated by Asset Table, "Get Patch Scan" button
        "/runPatchScan" (controller: 'vulnerability', action:'runPatchScan')

        //Runs get Vulnerability Update using ACAS
        //Activated by Maintenance, "Get In Use Update" button
        "/getVulnUpdate" (controller: 'vulnerability', action:'getVulnUpdate')

        //Vulnerability Detail

        //Set patch vulnerability suspense dates (30 days, 20 days for critical)
        //Activated by Maintenance "Set Suspense Dates" button
        "/setSuspense" (controller: 'vulnerabilityDetail', action: 'setSuspense')
    }
}
