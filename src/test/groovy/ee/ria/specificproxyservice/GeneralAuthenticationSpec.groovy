package ee.ria.specificproxyservice

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.opensaml.saml.saml2.core.Assertion
import spock.lang.Unroll

import static org.junit.Assert.assertEquals

class GeneralAuthenticationSpec extends SpecificProxyServiceSpecification {
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
    @Feature("Estonian authentication means return LOA_HIGH")
    @Feature("AUTHENTICATION_REQUEST_OK")
    @Feature("AUTHENTICATION_RESPONSE_CREATE_LIGHTTOKEN")
    @Feature("AUTHENTICATION_RESPONSE_WITH_LIGHTTOKEN")
    @Feature("AUTHENTICATION_RESPONSE_CREATE_LIGHTRESPONSE_SUCCESS")
    @Feature("LOGIN_ENDPOINT_SUCCESSFUL_LOGIN")
    @Feature("LOGIN_ENDPOINT_LIGHTREQUEST")
    @Feature("LOGIN_ENDPOINT_INPUT_VALIDATION")
    @Feature("AUTHENTICATION_REQUEST_PROXY_ENDPOINT")
    @Feature("CONSENT_ENDPOINT_USER_AGREE")
    def "Successful natural person authentication with Mobile-ID"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response specificProxyResponse = Steps.startAuthProcessInEidasNode(flow, samlRequest)
        Response taraInitResponse = Steps.startAuthProcessInTara(flow, specificProxyResponse)
        Response midAuthAcceptResponse = Steps.authenticateWithMidAndFollowRedirects(flow, taraInitResponse)
        Response taraAuthenticationResponse = Steps.userConsentAndFollowRedirects(flow, midAuthAcceptResponse)
        Response eidasResponse = Steps.finishAuthProcessInEidasNode(flow, taraAuthenticationResponse.getHeader("Location"))

        Assertion assertion = SamlResponseUtils.getSamlAssertionFromResponse(eidasResponse, flow.connector.encryptionCredential)

        assertEquals("Correct LOA is returned", loa_level, SamlUtils.getLoaValue(assertion))
        assertEquals("Correct family name is returned", familyName, SamlUtils.getAttributeValue(assertion, FN_FAMILY))
        assertEquals("Correct first name is returned", firstName, SamlUtils.getAttributeValue(assertion, FN_FIRST))
        assertEquals("Correct id code is returned", personalNumber, SamlUtils.getAttributeValue(assertion, FN_PNO))
        assertEquals("Correct birth date is returned", dateOfBirth, SamlUtils.getAttributeValue(assertion, FN_DATE))

        where:
        familyName                   || firstName     || personalNumber      || dateOfBirth  || loa_level
        "O’CONNEŽ-ŠUSLIK TESTNUMBER" || "MARY ÄNN"    || "EE/CA/60001019906" || "2000-01-01" || "http://eidas.europa.eu/LoA/high"
    }

    @Unroll
    @Feature("LOGIN_ENDPOINT_FAILED_LOGIN")
    @Feature("PROCESS_ERRORS")
    def "cancel authentication in IDP"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response specificProxyResponse = Steps.startAuthProcessInEidasNode(flow, samlRequest)
        Steps.startAuthProcessInTara(flow, specificProxyResponse)
        Response cancelResponse = Steps.userCancelAndFollowRedirects(flow)
        Response eidasResponse = Steps.finishAuthProcessInEidasNode(flow, cancelResponse.getHeader("Location"))

        org.opensaml.saml.saml2.core.Response samlResponseObj = SamlResponseUtils.getSamlResponseFromResponse(eidasResponse)

        assertEquals("The request could not be performed due to an error on the part of the requester.", samlStatusCode, samlResponseObj.status.statusCode.value)
        assertEquals("The SAML responder or SAML authority is able to process the request but has chosen not to respond.", samlSubStatusCode, samlResponseObj.status.statusCode.statusCode.value)
        assertEquals("Reason for unsuccessful authentication.", samlStatusMessage, samlResponseObj.status.statusMessage.message)

        where:
        samlStatusCode                                 || samlSubStatusCode                                  || samlStatusMessage
        "urn:oasis:names:tc:SAML:2.0:status:Requester" || "urn:oasis:names:tc:SAML:2.0:status:RequestDenied" || "User canceled the authentication process"
      }

    @Unroll
    @Feature("LOGIN_ENDPOINT_FAILED_LOGIN")
    @Feature("CONSENT_ENDPOINT_USER_CANCEL")
    def "user can deny the usage of personal data"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response specificProxyResponse = Steps.startAuthProcessInEidasNode(flow, samlRequest)
        Response taraInitResponse = Steps.startAuthProcessInTara(flow, specificProxyResponse)
        Response midStatusResponse = Steps.authenticateWithMidAndFollowRedirects(flow, taraInitResponse)
        Response taraAuthenticationResponse = Steps.userDenyConsentAndFollowRedirects(flow, midStatusResponse)
        Response eidasResponse = Steps.finishAuthProcessInEidasNode(flow, taraAuthenticationResponse.getHeader("Location"))

        org.opensaml.saml.saml2.core.Response samlResponseObj = SamlResponseUtils.getSamlResponseFromResponse(eidasResponse)

        assertEquals("The request could not be performed due to an error on the part of the requester.", samlStatusCode, samlResponseObj.status.statusCode.value)
        assertEquals("The SAML responder or SAML authority is able to process the request but has chosen not to respond.", samlSubStatusCode, samlResponseObj.status.statusCode.statusCode.value)
        assertEquals("Reason for unsuccessful authentication.", samlStatusMessage, samlResponseObj.status.statusMessage.message)

        where:
        samlStatusCode                                 || samlSubStatusCode                                  || samlStatusMessage
        "urn:oasis:names:tc:SAML:2.0:status:Requester" || "urn:oasis:names:tc:SAML:2.0:status:RequestDenied" || "User canceled the authentication process"
      }

    @Feature("Estonian authentication means return LOA_HIGH")
    @Feature("AUTHENTICATION_REQUEST_OK")
    @Feature("AUTHENTICATION_RESPONSE_CREATE_LIGHTTOKEN")
    @Feature("AUTHENTICATION_RESPONSE_WITH_LIGHTTOKEN")
    @Feature("AUTHENTICATION_RESPONSE_CREATE_LIGHTRESPONSE_SUCCESS")
    @Feature("LOGIN_ENDPOINT_SUCCESSFUL_LOGIN")
    @Feature("LOGIN_ENDPOINT_LIGHTREQUEST")
    @Feature("LOGIN_ENDPOINT_INPUT_VALIDATION")
    @Feature("AUTHENTICATION_REQUEST_PROXY_ENDPOINT")
    @Feature("CONSENT_ENDPOINT_USER_AGREE")
    def "Successful legal person authentication with Mobile-ID"() {
        expect:
        String samlRequest = Steps.getLegalPersonAuthnRequest(flow, "DEMO-SP-CA")
        Response specificProxyResponse = Steps.startAuthProcessInEidasNode(flow, samlRequest)
        Response taraInitResponse = Steps.startAuthProcessInTara(flow, specificProxyResponse)
        Response midAuthAcceptResponse = Steps.authenticateWithMidAndFollowRedirects(flow, taraInitResponse)
        Response getLegalEntityListResponse = Steps.getLegalEntityList(flow, midAuthAcceptResponse)
        Response legalPersonSelectionResponse = Steps.selectLegalEntity(flow, getLegalEntityListResponse.body().jsonPath().get("legalPersons[0].legalPersonIdentifier"))
        String legalName = getLegalEntityListResponse.body().jsonPath().get("legalPersons[0].legalName")
        Response taraAuthenticationResponse = Steps.userConsentAndFollowRedirects(flow, legalPersonSelectionResponse)
        Response eidasResponse = Steps.finishAuthProcessInEidasNode(flow, taraAuthenticationResponse.getHeader("Location"))

        Assertion assertion = SamlResponseUtils.getSamlAssertionFromResponse(eidasResponse, flow.connector.encryptionCredential)

        assertEquals("Correct LOA is returned", "http://eidas.europa.eu/LoA/high", SamlUtils.getLoaValue(assertion))
        assertEquals("Either legal name from dev or test business register", SamlUtils.getAttributeValue(assertion, "LegalName"), legalName)
        assertEquals("Correct legal person identifier is returned", "EE/CA/" + getLegalEntityListResponse.body().jsonPath().get("legalPersons[0].legalPersonIdentifier"), SamlUtils.getAttributeValue(assertion, "LegalPersonIdentifier"))
    }

    @Feature("Estonian authentication means return LOA_HIGH")
    @Feature("AUTHENTICATION_REQUEST_OK")
    @Feature("AUTHENTICATION_RESPONSE_CREATE_LIGHTTOKEN")
    @Feature("AUTHENTICATION_RESPONSE_WITH_LIGHTTOKEN")
    @Feature("AUTHENTICATION_RESPONSE_CREATE_LIGHTRESPONSE_SUCCESS")
    @Feature("LOGIN_ENDPOINT_SUCCESSFUL_LOGIN")
    @Feature("LOGIN_ENDPOINT_LIGHTREQUEST")
    @Feature("LOGIN_ENDPOINT_INPUT_VALIDATION")
    @Feature("AUTHENTICATION_REQUEST_PROXY_ENDPOINT")
    @Feature("CONSENT_ENDPOINT_USER_AGREE")
    def "not supported optional attributes requested on legal person authentication"() {
        expect:
        String samlRequest = Steps.getOptionalLegalPersonAuthnRequest(flow, "DEMO-SP-CA")
        Response specificProxyResponse = Steps.startAuthProcessInEidasNode(flow, samlRequest)
        Response taraInitResponse = Steps.startAuthProcessInTara(flow, specificProxyResponse)
        Response midAuthAcceptResponse = Steps.authenticateWithMidAndFollowRedirects(flow, taraInitResponse)
        Response getLegalEntityListResponse = Steps.getLegalEntityList(flow, midAuthAcceptResponse)
        Response legalPersonSelectionResponse = Steps.selectLegalEntity(flow, getLegalEntityListResponse.body().jsonPath().get("legalPersons[0].legalPersonIdentifier"))
        String legalName = getLegalEntityListResponse.body().jsonPath().get("legalPersons[0].legalName")
        Response taraAuthenticationResponse = Steps.userConsentAndFollowRedirects(flow, legalPersonSelectionResponse)
        Response eidasResponse = Steps.finishAuthProcessInEidasNode(flow, taraAuthenticationResponse.getHeader("Location"))

        Assertion assertion = SamlResponseUtils.getSamlAssertionFromResponse(eidasResponse, flow.connector.encryptionCredential)

        assertEquals("Correct LOA is returned", "http://eidas.europa.eu/LoA/high", SamlUtils.getLoaValue(assertion))
        assertEquals("Either legal name from dev or test business register", SamlUtils.getAttributeValue(assertion, "LegalName"), legalName)
        assertEquals("Correct legal person identifier is returned", "EE/CA/" + getLegalEntityListResponse.body().jsonPath().get("legalPersons[0].legalPersonIdentifier"), SamlUtils.getAttributeValue(assertion, "LegalPersonIdentifier"))
    }

    @Unroll
    @Feature("LOGIN_ENDPOINT_FAILED_LOGIN")
    @Feature("CONSENT_ENDPOINT_USER_CANCEL")
    def "User denies consent on legal person authentication with Mobile-ID"() {
        expect:
        String samlRequest = Steps.getLegalPersonAuthnRequest(flow, "DEMO-SP-CA")
        Response specificProxyResponse = Steps.startAuthProcessInEidasNode(flow, samlRequest)
        Response taraInitResponse = Steps.startAuthProcessInTara(flow, specificProxyResponse)
        Response midAuthAcceptResponse = Steps.authenticateWithMidAndFollowRedirects(flow, taraInitResponse)
        Response getLegalEntityListResponse = Steps.getLegalEntityList(flow, midAuthAcceptResponse)
        Response legalPersonSelectionResponse = Steps.selectLegalEntity(flow, getLegalEntityListResponse.body().jsonPath().get("legalPersons[0].legalPersonIdentifier"))
        Response taraAuthenticationResponse = Steps.userDenyConsentAndFollowRedirects(flow, legalPersonSelectionResponse)
        Response eidasResponse = Steps.finishAuthProcessInEidasNode(flow, taraAuthenticationResponse.getHeader("Location"))

        org.opensaml.saml.saml2.core.Response samlResponseObj = SamlResponseUtils.getSamlResponseFromResponse(eidasResponse)

        assertEquals("The request could not be performed due to an error on the part of the requester.", samlStatusCode, samlResponseObj.status.statusCode.value)
        assertEquals("The SAML responder or SAML authority is able to process the request but has chosen not to respond.", samlSubStatusCode, samlResponseObj.status.statusCode.statusCode.value)
        assertEquals("Reason for unsuccessful authentication.", samlStatusMessage, samlResponseObj.status.statusMessage.message)

        where:
        samlStatusCode                                 || samlSubStatusCode                                  || samlStatusMessage
        "urn:oasis:names:tc:SAML:2.0:status:Requester" || "urn:oasis:names:tc:SAML:2.0:status:RequestDenied" || "User canceled the authentication process"
    }

    @Unroll
    @Feature("LOGIN_ENDPOINT_FAILED_LOGIN")
    @Feature("PROCESS_ERRORS")
    def "cancel legal person authentication in IDP"() {
        expect:
        String samlRequest = Steps.getLegalPersonAuthnRequest(flow, "DEMO-SP-CA")
        Response specificProxyResponse = Steps.startAuthProcessInEidasNode(flow, samlRequest)
        Steps.startAuthProcessInTara(flow, specificProxyResponse)
        Response cancelResponse = Steps.userCancelAndFollowRedirects(flow)
        Response eidasResponse = Steps.finishAuthProcessInEidasNode(flow, cancelResponse.getHeader("Location"))

        org.opensaml.saml.saml2.core.Response samlResponseObj = SamlResponseUtils.getSamlResponseFromResponse(eidasResponse)

        assertEquals("The request could not be performed due to an error on the part of the requester.", samlStatusCode, samlResponseObj.status.statusCode.value)
        assertEquals("The SAML responder or SAML authority is able to process the request but has chosen not to respond.", samlSubStatusCode, samlResponseObj.status.statusCode.statusCode.value)
        assertEquals("Reason for unsuccessful authentication.", samlStatusMessage, samlResponseObj.status.statusMessage.message)

        where:
        samlStatusCode                                 || samlSubStatusCode                                  || samlStatusMessage
        "urn:oasis:names:tc:SAML:2.0:status:Requester" || "urn:oasis:names:tc:SAML:2.0:status:RequestDenied" || "User canceled the authentication process"
    }
}
