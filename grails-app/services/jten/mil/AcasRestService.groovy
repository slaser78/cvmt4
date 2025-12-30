package jten.mil


import grails.gorm.transactions.Transactional
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import grails.core.*
import org.apache.hc.client5.http.classic.methods.HttpPost
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient
import org.apache.hc.client5.http.impl.classic.HttpClients
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder
import org.apache.hc.core5.http.io.entity.EntityUtils
import org.apache.hc.core5.http.io.entity.StringEntity
import org.apache.hc.core5.ssl.SSLContexts

@Transactional
class AcasRestService {
    AssetStigVulnStatus assetStigVulnStatus
    GrailsApplication grailsApplication
    def getConnection() {
        def json = JsonOutput.toJson([username: grailsApplication.config.getProperty('acasName', String.class),
                                      password: grailsApplication.config.getProperty('acasPassword', String.class)])

        def sslContext1 = SSLContexts.createSystemDefault()

        def tlsStrategy = ClientTlsStrategyBuilder.create()
                .setSslContext(sslContext1)
                .buildClassic()

        PoolingHttpClientConnectionManager connectionManager =
                PoolingHttpClientConnectionManagerBuilder.create()
                        .setTlsSocketStrategy(tlsStrategy)
                        .build()

        CloseableHttpClient httpClient = HttpClients.custom()
                .setConnectionManager(connectionManager)
                .build()

        def cookieValues = null
        def token
        String token1 = null
        def entities = null
        try {
            HttpPost httpPost = new HttpPost(grailsApplication.config.getProperty('acasUrl', String.class)+"/rest/token")
            httpPost.addHeader("Content-Type", "application/json")
            StringEntity entity = new StringEntity(json)
            httpPost.setEntity(entity)
            httpClient.execute(httpPost, response -> {
                cookieValues = response.getHeaders("Set-Cookie")
                entities = EntityUtils.toString(response.getEntity())
            })
            def jsonSlurper = new JsonSlurper()
            def object = jsonSlurper.parseText(entities)
            token = object.response.token
            token1 = token.toString()
        } catch (e) {
            log.error (e.getMessage())
        }
        String cookie = cookieValues[1]
        String cookie1 = cookie.replaceAll("Set-Cookie:","")
        String cookie2 = cookie1.replaceAll("SameSite=Strict","")
        Map <String, String> map1=["token":token1.trim()]
        Map<String,String> map2=["cookie":cookie2.trim()]
        Map map3 = map1  + map2
        return map3
    }
}