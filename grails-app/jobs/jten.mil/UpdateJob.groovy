import grails.async.Promise

import static grails.async.Promises.task

class UpdateJob {
    def assetService
    def acasRestService
    def vulnerability2Service
    def scanService
    def lookupService
    def mitigation2Service
    def elasticService

    static triggers = {
     cron name: 'CompUpdateTrigger', cronExpression: "0 00 05 * * ?"
    }

    def execute() {
        def acasConnection = acasRestService.getConnection()
        if (acasConnection.cookie != null) {
            //import new assets from ACAS
            Promise p1 = task {
                log.warn ("Start All Updates")
                log.warn("Start Asset Lookups.")
                lookupService.getName()
            }
            p1.onError { Throwable err1 ->
                log.error("An error occurred ${err1.message}")
            }
            p1.onComplete {
                log.warn("Finish Asset Lookups")
                Promise p2 = task {
                    log.warn("Start Asset Updates.")
                    assetService.getAssets(acasConnection)
                }
                p2.onError { Throwable err2 ->
                    log.error("An error occurred ${err2.message}")
                }
                p2.onComplete {
                    log.warn("Finish Asset Updates")
                    //Get New Vulnerabilities
                    log.warn("Start Vulnerability Updates")
                    Promise p3 = task {
                        vulnerability2Service.getPatchVulns(acasConnection)
                    }
                    p3.onError { Throwable err3 ->
                        log.error("An error occurred ${err3.message}")
                    }
                    p3.onComplete {
                        log.warn("Finish Vulnerability Updates")
                        //Get asset-vulnerability updates
                        Promise p4 = task {
                            log.warn("Start Asset-Vulnerability Updates")
                            vulnerability2Service.getAssetPatchVulns(acasConnection)
                        }
                        p4.onError { Throwable err4 ->
                            log.error("An error occurred ${err4.message}")
                        }
                        p4.onComplete {
                            log.warn("Finish Asset-Vulnerability updates")
                            Promise p4a = task {
                                log.warn ("Start Vulnerability (with Asset) Updates")
                                vulnerability2Service.getVulnerabilityUpdate(acasConnection)
                            }
                            p4a.onError { Throwable err4a ->
                                log.error("An error occurred ${err4a.message}")
                            }
                            p4a.onComplete {
                                log.warn ("Finish Vulnerability (with Asset) Updates")
                                Promise p5 = task {
                                    log.warn ("Start Check Asset Patch Vulnerabilities")
                                    vulnerability2Service.checkVulnAsset()
                                }
                                p5.onError { Throwable err5 ->
                                    log.error("An error occurred ${err5.message}")
                                }
                                p5.onComplete {
                                    log.warn ("Finish Check Asset Patch Vulnerabilities")
                                    //Delete Empty Mitigations
                                    Promise p6 = task {
                                    log.warn("Start Delete Empty Mitigations")
                                    mitigation2Service.delMit()
                                }
                                    p6.onError { Throwable err6 ->
                                        log.error("An error occurred ${err6.message}")
                                    }
                                    p6.onComplete {
                                        log.warn("Finish Delete Empty Mitigations")
                                        //Get Latest Scores
                                        Promise p7 = task {
                                            log.warn("Start Update Scores")
                                            assetService.getScore()
                                        }
                                        p7.onError { Throwable err7 ->
                                            log.error("An error occurred ${err7.message}")
                                        }
                                        p7.onComplete {
                                            log.warn("Finish Update Scores")
                                            //Update Subnets
                                            Promise p8 = task {
                                                log.warn("Start Update Subnets")
                                                assetService.setSubnets()
                                            }
                                            p8.onError { Throwable err8 ->
                                                log.error("An error occurred ${err8.message}")
                                            }
                                            p8.onComplete {
                                                log.warn("Finish Update Subnets")
                                                //upload asset vulnerability info to Elastic
                                                Promise p9 = task {
                                                    log.warn("Start Get Asset Patch Details")
                                                    scanService.getAssetScanDetails1(acasConnection)
                                                }
                                                p9.onError { Throwable err9 ->
                                                    log.error("An error occurred: ${err9.message}")
                                                }
                                                p9.onComplete {
                                                    log.warn("Finish Get Asset Patch Details")
                                                    Promise p10 = task {
                                                        log.warn("Start Get Patch Scan Details")
                                                        scanService.getScanDetails(acasConnection)
                                                    }
                                                    p10.onError { Throwable err10 ->
                                                        log.error("An error occurred: ${err10.message}")
                                                    }
                                                    p10.onComplete {
                                                        log.warn("Finish Get Patch Scan Details")
                                                        Promise p11 = task {
                                                            log.warn("Start Set Suspense Dates")
                                                            vulnerability2Service.setSuspense()
                                                        }
                                                        p11.onError { Throwable err11 ->
                                                            log.error("An error occurred: ${err11.message}")
                                                        }
                                                        p11.onComplete {
                                                            log.warn("Finish Set Suspense Dates")
                                                            //Upload patch vulnerabilities to Elastic
                                                            Promise p12 = task {
                                                                log.warn("Start Device Type Upload")
                                                                elasticService.elasticDeviceTypeUpload()
                                                            }
                                                            p12.onError { Throwable err12 ->
                                                                log.error("An error occurred: ${err12.message}")
                                                            }
                                                            p12.onComplete {
                                                                log.warn("Finish Device Type Upload")
                                                                //Upload STIG vulnerabilities to Elastic
                                                                Promise p13 = task {
                                                                    log.warn("Start Elastic Asset Info Upload")
                                                                    elasticService.elasticAssetUpload()
                                                                }
                                                                p13.onError { Throwable err13 ->
                                                                    log.error("An error occurred: ${err13.message}")
                                                                }
                                                                p13.onComplete {
                                                                    log.warn("Finish Elastic Asset Info Upload")
                                                                    //Upload Asset list to Elastic
                                                                    Promise p14 = task {
                                                                        log.warn("Start Elastic STIG Upload")
                                                                        elasticService.elasticStigUpload()
                                                                    }
                                                                    p14.onError { Throwable err14 ->
                                                                        log.error("An error occurred: ${err14.message}")
                                                                    }
                                                                    p14.onComplete {
                                                                        log.warn("Finish Elastic STIG Upload")
                                                                        //Upload Asset STIG info to Elastic
                                                                        Promise p15 = task {
                                                                            log.warn("Start Patch Upload to Elastic")
                                                                            elasticService.elasticPatchUpload()
                                                                        }
                                                                        p15.onError { Throwable err15 ->
                                                                            log.error("An error occurred: ${err15.message}")
                                                                        }
                                                                        p15.onComplete {
                                                                            log.warn "Finish Patch Upload to Elastic"
                                                                            Promise p16 = task {
                                                                                log.warn("Start ACAS asset check")
                                                                                assetService.checkAcas(acasConnection)
                                                                            }
                                                                            p16.onError {Throwable err16 ->
                                                                                log.error ("An error occurred: ${err16.message}")
                                                                            }
                                                                            p16.onComplete {
                                                                                log.warn ("Finish ACAS asset check")
                                                                            }
                                                                            log.warn("Finish All Updates")
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            log.error ("ACAS Connection failed")
        }
    }
}
