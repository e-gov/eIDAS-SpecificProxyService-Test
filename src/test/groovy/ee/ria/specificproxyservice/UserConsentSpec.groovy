package ee.ria.specificproxyservice

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Unroll

import static org.junit.Assert.assertTrue

class UserConsentSpec extends SpecificProxyServiceSpecification {


    Flow flow = new Flow(props)

    def setup() {
        flow.connector.signatureCredential = signatureCredential
        flow.connector.encryptionCredential = encryptionCredential
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("CONSENT_VIEW")
    def "Proper information is shown in consent view"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, spName)
        Response specificProxyResponse = Steps.startAuthProcessInEidasNode(flow, samlRequest)
        Response taraInitResponse = Steps.startAuthProcessInTara(flow, specificProxyResponse)
        Steps.authenticateWithMidAndFollowRedirects(flow, taraInitResponse)
        Response response = Requests.startConsentFlow(flow, flow.specificProxyService.taraBaseUrl + "/auth/accept")
        Response response2 = Requests.followRedirectWithCsrfCookie(flow, response.getHeader("location"))
        flow.setOauth2_consent_csrf(response2.getCookie("oauth2_consent_csrf"))

        Response consentViewResponse = Requests.followRedirect(flow, response2.getHeader("location"))

        List<String> identityFields = consentViewResponse.body().htmlPath().getList("**.findAll {th -> th.@colspan == '1'}")

        assertTrue(identityFields.containsAll("Isikukood:", "Perenimi:", "Eesnimi:", "Sünniaeg:"))
        assertTrue(identityFields.containsAll("60001019906", "O’CONNEŽ-ŠUSLIK TESTNUMBER", "MARY ÄNN", "01.01.2000"))

        where:
        spName       || familyName                   || firstName  || personalNumber      || dateOfBirth  || loa_level
        "DEMO-SP-CA" || "O’CONNEŽ-ŠUSLIK TESTNUMBER" || "MARY ÄNN" || "60001019906" || "2000-01-01" || "http://eidas.europa.eu/LoA/high"
    }
}

