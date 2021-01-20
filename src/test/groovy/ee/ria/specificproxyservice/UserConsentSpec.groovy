package ee.ria.specificproxyservice

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Unroll

import static org.junit.Assert.assertEquals

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
        Response response = Steps.authenticateWithMidAndFollowRedirects(flow, taraInitResponse)
        Response response2 = Requests.followRedirectWithCsrfCookie(flow, response.getHeader("location"))
        flow.setOauth2_consent_csrf(response2.getCookie("oauth2_consent_csrf"))

        Response consentViewResponse = Requests.followRedirect(flow, response2.getHeader("location"))

        assertEquals("Correct ID code is returned", personalNumber, consentViewResponse.body().htmlPath().get("**.find {it.@id == 'natural-person-id-code'}").toString().trim())
        assertEquals("Correct family name is returned", familyName, consentViewResponse.body().htmlPath().get("**.find {it.@id == 'natural-person-surname'}").toString().trim())
        assertEquals("Correct first name is returned", firstName, consentViewResponse.body().htmlPath().get("**.find {it.@id == 'natural-person-given-name'}").toString().trim())
        assertEquals("Correct date of birth is returned", dateOfBirth, consentViewResponse.body().htmlPath().get("**.find {it.@id == 'natural-person-date-of-birth'}").toString().trim())

        where:
        spName       || familyName                   || firstName  || personalNumber || dateOfBirth
        "DEMO-SP-CA" || "O’CONNEŽ-ŠUSLIK TESTNUMBER" || "MARY ÄNN" || "60001019906"  || "01.01.2000"
    }

    @Unroll
    @Feature("CONSENT_VIEW")
    def "Proper information is shown in legal person consent view"() {
        expect:
        String samlRequest = Steps.getLegalPersonAuthnRequest(flow, spName)
        Response specificProxyResponse = Steps.startAuthProcessInEidasNode(flow, samlRequest)
        Response taraInitResponse = Steps.startAuthProcessInTara(flow, specificProxyResponse)
        Response midAuthAcceptResponse = Steps.authenticateWithMidAndFollowRedirects(flow, taraInitResponse)
        Response legalPersonSelectionResponse = Steps.selectLegalEntity(flow, midAuthAcceptResponse, legalIdentifier)
        Response response2 = Requests.followRedirectWithCsrfCookie(flow, legalPersonSelectionResponse.getHeader("location"))
        flow.setOauth2_consent_csrf(response2.getCookie("oauth2_consent_csrf"))

        Response consentViewResponse = Requests.followRedirect(flow, response2.getHeader("location"))

        assertEquals("Correct ID code is returned", personalNumber, consentViewResponse.body().htmlPath().get("**.find {it.@id == 'natural-person-id-code'}").toString().trim())
        assertEquals("Correct family name is returned", familyName, consentViewResponse.body().htmlPath().get("**.find {it.@id == 'natural-person-surname'}").toString().trim())
        assertEquals("Correct first name is returned", firstName, consentViewResponse.body().htmlPath().get("**.find {it.@id == 'natural-person-given-name'}").toString().trim())
        assertEquals("Correct date of birth is returned", dateOfBirth, consentViewResponse.body().htmlPath().get("**.find {it.@id == 'natural-person-date-of-birth'}").toString().trim())
        assertEquals("Correct legal person name is returned", legalName, consentViewResponse.body().htmlPath().get("**.find {it.@id == 'legal-person-name'}").toString().trim())
        assertEquals("Correct legal person identifier is returned", legalIdentifier, consentViewResponse.body().htmlPath().get("**.find {it.@id == 'legal-person-identifier'}").toString().trim())

        where:
        spName       || familyName                   || firstName  || personalNumber || dateOfBirth  || legalName || legalIdentifier
        "DEMO-SP-CA" || "O’CONNEŽ-ŠUSLIK TESTNUMBER" || "MARY ÄNN" || "60001019906"  || "01.01.2000" || "täisühing VAVILOV" || "10910878"
    }
}

