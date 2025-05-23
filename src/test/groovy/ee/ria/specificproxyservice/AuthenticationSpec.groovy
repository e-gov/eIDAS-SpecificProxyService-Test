package ee.ria.specificproxyservice

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.opensaml.saml.saml2.core.Assertion
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration
import org.opensaml.saml.saml2.core.NameIDType
import spock.lang.Ignore
import spock.lang.Unroll

import static org.junit.Assert.assertEquals


class AuthenticationSpec extends SpecificProxyServiceSpecification {
    public static final String FN_DATE = "DateOfBirth"
    public static final String FN_PNO = "PersonIdentifier"
    public static final String FN_FAMILY = "FamilyName"
    public static final String FN_FIRST = "FirstName"

    Flow flow = new Flow(props)

    def setup() {
        flow.connector.signatureCredential = signatureCredential
        flow.connector.encryptionCredential = encryptionCredential
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("eIDAS-Node implementations MUST support the following SAML 2.0 name identifier formats")
    def "request authentication with name identifier format: #nameIdFormat"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA", "http://eidas.europa.eu/LoA/high", AuthnContextComparisonTypeEnumeration.MINIMUM, nameIdFormat)
        Response specificProxyResponse = Steps.startAuthProcessInEidasNode(flow, samlRequest)
        Response taraInitResponse = Steps.startAuthProcessInTara(flow, specificProxyResponse)
        Response midAuthAcceptResponse = Steps.authenticateWithMidAndFollowRedirects(flow, taraInitResponse)
        Response taraAuthenticationResponse = Steps.userConsentAndFollowRedirects(flow, midAuthAcceptResponse)
        Response eidasResponse = Steps.finishAuthProcessInEidasNode(flow, taraAuthenticationResponse.getHeader("Location"))

        Assertion assertion = SamlResponseUtils.getSamlAssertionFromResponse(eidasResponse, flow.connector.encryptionCredential)

        assertEquals("Correct LOA is returned", "http://eidas.europa.eu/LoA/high", SamlUtils.getLoaValue(assertion))
        assertEquals("Correct family name is returned", familyName, SamlUtils.getAttributeValue(assertion, FN_FAMILY))
        assertEquals("Correct first name is returned", firstName, SamlUtils.getAttributeValue(assertion, FN_FIRST))
        assertEquals("Correct id code is returned", personalNumber, SamlUtils.getAttributeValue(assertion, FN_PNO))
        assertEquals("Correct birth date is returned", dateOfBirth, SamlUtils.getAttributeValue(assertion, FN_DATE))
        assertEquals("Correct nameIdFormat is returned", nameIdFormat, SamlUtils.getSubjectNameIdFormatValue(assertion))

        where:
        nameIdFormat           || familyName                   || firstName     || personalNumber      || dateOfBirth  || loa_level
        NameIDType.TRANSIENT   || "O’CONNEŽ-ŠUSLIK TESTNUMBER" || "MARY ÄNN"    || "EE/CA/60001019906" || "2000-01-01" || "http://eidas.europa.eu/LoA/high"
        NameIDType.PERSISTENT  || "O’CONNEŽ-ŠUSLIK TESTNUMBER" || "MARY ÄNN"    || "EE/CA/60001019906" || "2000-01-01" || "http://eidas.europa.eu/LoA/high"
        NameIDType.UNSPECIFIED || "O’CONNEŽ-ŠUSLIK TESTNUMBER" || "MARY ÄNN"    || "EE/CA/60001019906" || "2000-01-01" || "http://eidas.europa.eu/LoA/high"
    }

    @Unroll
    @Feature("eIDAS-Node implementations MUST support requests without name identifier formats attribute")
    def "request authentication without name identifier format"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithoutNameIdFormat(flow, "DEMO-SP-CA", "http://eidas.europa.eu/LoA/high", AuthnContextComparisonTypeEnumeration.MINIMUM)
        Response specificProxyResponse = Steps.startAuthProcessInEidasNode(flow, samlRequest)
        Response taraInitResponse = Steps.startAuthProcessInTara(flow, specificProxyResponse)
        Response midAuthAcceptResponse = Steps.authenticateWithMidAndFollowRedirects(flow, taraInitResponse)
        Response taraAuthenticationResponse = Steps.userConsentAndFollowRedirects(flow, midAuthAcceptResponse)
        Response eidasResponse = Steps.finishAuthProcessInEidasNode(flow, taraAuthenticationResponse.getHeader("Location"))

        Assertion assertion = SamlResponseUtils.getSamlAssertionFromResponse(eidasResponse, flow.connector.encryptionCredential)

        assertEquals("Correct LOA is returned", "http://eidas.europa.eu/LoA/high", SamlUtils.getLoaValue(assertion))
        assertEquals("Correct family name is returned", familyName, SamlUtils.getAttributeValue(assertion, FN_FAMILY))
        assertEquals("Correct first name is returned", firstName, SamlUtils.getAttributeValue(assertion, FN_FIRST))
        assertEquals("Correct id code is returned", personalNumber, SamlUtils.getAttributeValue(assertion, FN_PNO))
        assertEquals("Correct birth date is returned", dateOfBirth, SamlUtils.getAttributeValue(assertion, FN_DATE))
        assertEquals("Correct nameIdFormat is returned", nameIdFormat, SamlUtils.getSubjectNameIdFormatValue(assertion))

        where:
        nameIdFormat           || familyName                   || firstName     || personalNumber      || dateOfBirth  || loa_level
        NameIDType.UNSPECIFIED || "O’CONNEŽ-ŠUSLIK TESTNUMBER" || "MARY ÄNN"    || "EE/CA/60001019906" || "2000-01-01" || "http://eidas.europa.eu/LoA/high"
    }

    @Unroll
    @Feature("To support reuse of eIDAS-Node infrastructure for non-notified eID schemes, Member States MAY support other URIs as Authentication Context")
    def "request authentication with supported comparison: #comparisonLevel and requested LOA: #requestLoa"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA", requestLoa, comparisonLevel)
        Response specificProxyResponse = Steps.startAuthProcessInEidasNode(flow, samlRequest)
        Response taraInitResponse = Steps.startAuthProcessInTara(flow, specificProxyResponse)
        Response midAuthAcceptResponse = Steps.authenticateWithMidAndFollowRedirects(flow, taraInitResponse)
        Response taraAuthenticationResponse = Steps.userConsentAndFollowRedirects(flow, midAuthAcceptResponse)
        Response eidasResponse = Steps.finishAuthProcessInEidasNode(flow, taraAuthenticationResponse.getHeader("Location"))

        Assertion assertion = SamlResponseUtils.getSamlAssertionFromResponse(eidasResponse, flow.connector.encryptionCredential)

        assertEquals("Correct LOA is returned", responseLoa, SamlUtils.getLoaValue(assertion))

        where:
        comparisonLevel                               | requestLoa                                   || responseLoa
        AuthnContextComparisonTypeEnumeration.MINIMUM | "http://eidas.europa.eu/LoA/high"            || "http://eidas.europa.eu/LoA/high"
    }

    @Unroll
    @Feature("EXACT comparison is allowed for not notified LOAs only")
    def "request authentication with not supported comparison: #comparisonLevel and requested LOA: #requestLoa"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA", requestLoa, comparisonLevel)
        Response response = Requests.colleagueRequest(flow, samlRequest)

        assertEquals("Error is returned", errorResponse, response.body().htmlPath().get("**.find {it.@class == 'text-center'}"))

        where:
        comparisonLevel                               | requestLoa                                   || errorResponse
        AuthnContextComparisonTypeEnumeration.EXACT   | "http://eidas.europa.eu/LoA/high"            || "202015 - invalid value for Level of Assurance"
    }

    @Ignore("AUT-2166")
    @Unroll
    @Feature("EXACT comparison is required for not notified LOAs")
    def "request authentication with required comparison for not notified schemas: #comparisonLevel and requested LOA: #requestLoa"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA", requestLoa, comparisonLevel)
        Response response = Requests.colleagueRequest(flow, samlRequest)

        org.opensaml.saml.saml2.core.Response samlResponseObj = SamlResponseUtils.getSamlResponseFromResponse(response)

        assertEquals("The request could not be performed due to an error on the part of the requester.", statusCode, samlResponseObj.status.statusCode.value)
        assertEquals("Reason for unsuccessful authentication.", errorMessage, samlResponseObj.status.statusMessage.message)

        where:
        comparisonLevel                               | requestLoa                                   || errorMessage || statusCode
        AuthnContextComparisonTypeEnumeration.EXACT   | "http://eidas.europa.eu/NotNotified/LoA/low" || "202015 - invalid value for Level of Assurance" || "urn:oasis:names:tc:SAML:2.0:status:Requester"
    }

    @Unroll
    @Feature("AUTHENTICATION_PROCESS_TYPE")
    def "request authentication with missing natural person identity attributes"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithMissingNaturalExtensions(flow, "DEMO-SP-CA")
        Response response = Requests.colleagueRequest(flow, samlRequest)

        assertEquals("Error is returned", "203021 - incomplete attribute set", response.body().htmlPath().get("**.find {it.@class == 'text-center'}"))
    }

    @Unroll
    @Feature("AUTHENTICATION_PROCESS_TYPE")
    def "request authentication with missing legal person identity attributes"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithMissingLegalExtensions(flow, "DEMO-SP-CA")
        Response response = Requests.colleagueRequest(flow, samlRequest)

        assertEquals("Error is returned", "203021 - incomplete attribute set", response.body().htmlPath().get("**.find {it.@class == 'text-center'}"))
    }

    @Unroll
    @Feature("AUTHENTICATION_PROCESS_TYPE")
    def "request authentication with legal and natural identity attributes"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithNaturalAndLegalExtensions(flow, "DEMO-SP-CA")
        Response specificProxyResponse = Steps.startAuthProcessInEidasNode(flow, samlRequest)

        assertEquals("400 status code is returned", 400, specificProxyResponse.statusCode())
        assertEquals("Proper message is returned", "Request may not contain both legal person and natural person attributes", specificProxyResponse.getBody().jsonPath().get("message"))
    }
}
