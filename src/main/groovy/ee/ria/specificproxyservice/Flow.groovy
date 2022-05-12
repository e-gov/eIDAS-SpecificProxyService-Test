package ee.ria.specificproxyservice

import groovy.transform.Canonical
import io.restassured.filter.cookie.CookieFilter
import org.opensaml.security.credential.Credential

@Canonical
class Flow {
    Properties properties
    SpecificProxyService specificProxyService
    Connector connector
    CookieFilter cookieFilter
    String sessionId
    String csrf
    String oauth2_authentication_csrf
    String oauth2_consent_csrf

    Flow(Properties properties) {
        this.properties = properties
        this.specificProxyService = new SpecificProxyService(properties)
        this.connector = new Connector(properties)
    }
}

@Canonical
class SpecificProxyService {
    String host
    String port
    String protocol
    String metadataUrl
    String authenticationRequestUrl
    String consentUrl
    String taraBaseUrl
    String heartbeatUrl

    @Lazy fullMetadataUrl = "${protocol}://${host}:${port}${metadataUrl}"
    @Lazy fullAuthenticationRequestUrl = "${protocol}://${host}:${port}${authenticationRequestUrl}"
    @Lazy fullheartbeatUrl = "${protocol}://${host}:${port}${heartbeatUrl}"

    SpecificProxyService(Properties properties) {
        this.host = properties."specificproxyservice.host"
        this.port = properties."specificproxyservice.port"
        this.protocol = properties."specificproxyservice.protocol"
        this.metadataUrl = properties."specificproxyservice.metadataUrl"
        this.authenticationRequestUrl = properties."specificproxyservice.authenticationRequestUrl"
        this.consentUrl=properties."specificproxyservice.consentUrl"
        this.heartbeatUrl=properties."specificproxyservice.heartbeatUrl"
    }

}

@Canonical
class Connector {
    String host
    String port
    String protocol
    String metadataUrl
    String authenticationResponseUrl
    Credential signatureCredential
    Credential encryptionCredential

    @Lazy fullMetadataUrl = "${protocol}://${host}:${port}${metadataUrl}"

    Connector(Properties properties) {
        this.host = properties."connector.host"
        this.port = properties."connector.port"
        this.protocol = properties."connector.protocol"
        this.metadataUrl = properties."connector.metadataUrl"
        this.authenticationResponseUrl = properties."connector.authenticationResponseUrl"

    }

}
