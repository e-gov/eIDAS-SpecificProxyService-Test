package ee.ria.specificproxyservice

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.opensaml.core.xml.schema.XSAny
import org.opensaml.saml.saml2.core.Assertion
import org.opensaml.saml.saml2.core.Attribute
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration
import org.opensaml.saml.saml2.core.NameIDType
import spock.lang.Unroll

import static org.junit.Assert.assertEquals

class AuthenticationSpec extends SpecificProxyServiceSpecification {
    public static final String FN_DATE = "DateOfBirth";
    public static final String FN_PNO = "PersonIdentifier";
    public static final String FN_FAMILY = "FamilyName";
    public static final String FN_FIRST = "FirstName";
    public static final String FN_ADDR = "CurrentAddress";
    public static final String FN_GENDER = "Gender";
    public static final String FN_BIRTH_NAME = "BirthName";
    public static final String FN_BIRTH_PLACE = "PlaceOfBirth";
    public static final String FN_LEGAL_NAME = "LegalName";
    public static final String FN_LEGAL_PNO = "LegalPersonIdentifier";


    Flow flow = new Flow(props)

    def setup() {
        flow.connector.signatureCredential = signatureCredential
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("Estonian authentication means return LOA_HIGH")
    def "request authentication with LOA level: #loa"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA" , loa)
        Response taraLoginPageResponse = Steps.startAuthProcessFollowRedirectsToTara(flow, samlRequest)
        Response consentPageResponse = Steps.authenticateWithMidAndFollowRedirects(flow, taraLoginPageResponse)
        Response authenticationResponse = Steps.userConsentAndFollowRedirects(flow, consentPageResponse)

        Assertion assertion = SamlResponseUtils.getSamlAssertionFromResponse(authenticationResponse, flow.connector.signatureCredential)

        assertEquals("Correct LOA is returned", loa_level, getLoaValue(assertion));
        assertEquals("Correct family name is returned", familyName, getAttributeValue(assertion, FN_FAMILY));
        assertEquals("Correct first name is returned", firstName, getAttributeValue(assertion, FN_FIRST));
        assertEquals("Correct id code is returned", personalNumber, getAttributeValue(assertion, FN_PNO));
        assertEquals("Correct birth date is returned", dateOfBirth, getAttributeValue(assertion, FN_DATE));


        where:
        loa                                      || familyName                   || firstName     || personalNumber      || dateOfBirth  || loa_level
        "http://eidas.europa.eu/LoA/low"         || "O’CONNEŽ-ŠUSLIK TESTNUMBER" || "MARY ÄNN"    || "EE/CA/60001019906" || "2000-01-01" || "http://eidas.europa.eu/LoA/high"
        "http://eidas.europa.eu/LoA/substantial" || "O’CONNEŽ-ŠUSLIK TESTNUMBER" || "MARY ÄNN"    || "EE/CA/60001019906" || "2000-01-01" || "http://eidas.europa.eu/LoA/high"
        "http://eidas.europa.eu/LoA/high"        || "O’CONNEŽ-ŠUSLIK TESTNUMBER" || "MARY ÄNN"    || "EE/CA/60001019906" || "2000-01-01" || "http://eidas.europa.eu/LoA/high"
    }

    @Unroll
    @Feature("eIDAS-Node implementations MUST support the following SAML 2.0 name identifier formats")
    def "request authentication with name identifier format: #nameIdFormat"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA", "http://eidas.europa.eu/LoA/high", AuthnContextComparisonTypeEnumeration.MINIMUM, nameIdFormat)
        Response taraLoginPageResponse = Steps.startAuthProcessFollowRedirectsToTara(flow, samlRequest)
        Response consentPageResponse = Steps.authenticateWithMidAndFollowRedirects(flow, taraLoginPageResponse)
        Response authenticationResponse = Steps.userConsentAndFollowRedirects(flow, consentPageResponse)

        Assertion assertion = SamlResponseUtils.getSamlAssertionFromResponse(authenticationResponse, flow.connector.signatureCredential)

        assertEquals("Correct LOA is returned", "http://eidas.europa.eu/LoA/high", getLoaValue(assertion));
        assertEquals("Correct family name is returned", familyName, getAttributeValue(assertion, FN_FAMILY));
        assertEquals("Correct first name is returned", firstName, getAttributeValue(assertion, FN_FIRST));
        assertEquals("Correct id code is returned", personalNumber, getAttributeValue(assertion, FN_PNO));
        assertEquals("Correct birth date is returned", dateOfBirth, getAttributeValue(assertion, FN_DATE));

        where:
        nameIdFormat           || familyName                   || firstName     || personalNumber      || dateOfBirth  || loa_level
        NameIDType.UNSPECIFIED || "O’CONNEŽ-ŠUSLIK TESTNUMBER" || "MARY ÄNN"    || "EE/CA/60001019906" || "2000-01-01" || "http://eidas.europa.eu/LoA/high"
        NameIDType.TRANSIENT   || "O’CONNEŽ-ŠUSLIK TESTNUMBER" || "MARY ÄNN"    || "EE/CA/60001019906" || "2000-01-01" || "http://eidas.europa.eu/LoA/high"
        NameIDType.PERSISTENT  || "O’CONNEŽ-ŠUSLIK TESTNUMBER" || "MARY ÄNN"    || "EE/CA/60001019906" || "2000-01-01" || "http://eidas.europa.eu/LoA/high"
    }

    @Unroll
    @Feature("To support reuse of eIDAS-Node infrastructure for non-notified eID schemes, Member States MAY support other URIs as Authentication Context")
    def "request authentication with comparison: #comparisonLevel and requested LOA: #loa"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA", loa, comparisonLevel)
        Response taraLoginPageResponse = Steps.startAuthProcessFollowRedirectsToTara(flow, samlRequest)
        Response consentPageResponse = Steps.authenticateWithMidAndFollowRedirects(flow, taraLoginPageResponse)
        Response authenticationResponse = Steps.userConsentAndFollowRedirects(flow, consentPageResponse)

        Assertion assertion = SamlResponseUtils.getSamlAssertionFromResponse(authenticationResponse, flow.connector.signatureCredential)

        assertEquals("Correct LOA is returned", loa_level, getLoaValue(assertion));
        assertEquals("Correct family name is returned", familyName, getAttributeValue(assertion, FN_FAMILY));
        assertEquals("Correct first name is returned", firstName, getAttributeValue(assertion, FN_FIRST));
        assertEquals("Correct id code is returned", personalNumber, getAttributeValue(assertion, FN_PNO));
        assertEquals("Correct birth date is returned", dateOfBirth, getAttributeValue(assertion, FN_DATE));

        where:
        comparisonLevel                               | loa                                          ||  familyName                  || firstName  || personalNumber      || dateOfBirth  || loa_level
        AuthnContextComparisonTypeEnumeration.MINIMUM | "http://eidas.europa.eu/LoA/low"             || "O’CONNEŽ-ŠUSLIK TESTNUMBER" || "MARY ÄNN" || "EE/CA/60001019906" || "2000-01-01" || "http://eidas.europa.eu/LoA/high"
        AuthnContextComparisonTypeEnumeration.EXACT   | "http://eidas.europa.eu/LoA/high"            || "O’CONNEŽ-ŠUSLIK TESTNUMBER" || "MARY ÄNN" || "EE/CA/60001019906" || "2000-01-01" || "http://eidas.europa.eu/LoA/high"
        AuthnContextComparisonTypeEnumeration.EXACT   | "http://eidas.europa.eu/NotNotified/LoA/low" || "O’CONNEŽ-ŠUSLIK TESTNUMBER" || "MARY ÄNN" || "EE/CA/60001019906" || "2000-01-01" || "http://eidas.europa.eu/LoA/high"
    }

    @Unroll
    @Feature("For indicating whether an authentication request is made by a private sector or public sector SPType MUST be present")
    def "request authentication with SPType: #spType"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA","http://eidas.europa.eu/LoA/high", AuthnContextComparisonTypeEnumeration.MINIMUM, NameIDType.UNSPECIFIED, spType)
        Response taraLoginPageResponse = Steps.startAuthProcessFollowRedirectsToTara(flow, samlRequest)
        Response consentPageResponse = Steps.authenticateWithMidAndFollowRedirects(flow, taraLoginPageResponse)
        Response authenticationResponse = Steps.userConsentAndFollowRedirects(flow, consentPageResponse)

        Assertion assertion = SamlResponseUtils.getSamlAssertionFromResponse(authenticationResponse, flow.connector.signatureCredential)

        assertEquals("Correct LOA is returned", "http://eidas.europa.eu/LoA/high", getLoaValue(assertion));
        assertEquals("Correct family name is returned", familyName, getAttributeValue(assertion, FN_FAMILY));
        assertEquals("Correct first name is returned", firstName, getAttributeValue(assertion, FN_FIRST));
        assertEquals("Correct id code is returned", personalNumber, getAttributeValue(assertion, FN_PNO));
        assertEquals("Correct birth date is returned", dateOfBirth, getAttributeValue(assertion, FN_DATE));

        where:
        spType         ||  familyName                  || firstName  || personalNumber      || dateOfBirth  || loa_level
        "public"       || "O’CONNEŽ-ŠUSLIK TESTNUMBER" || "MARY ÄNN" || "EE/CA/60001019906" || "2000-01-01" || "http://eidas.europa.eu/LoA/high"
        "private"      || "O’CONNEŽ-ŠUSLIK TESTNUMBER" || "MARY ÄNN" || "EE/CA/60001019906" || "2000-01-01" || "http://eidas.europa.eu/LoA/high"
        "not provided" || "O’CONNEŽ-ŠUSLIK TESTNUMBER" || "MARY ÄNN" || "EE/CA/60001019906" || "2000-01-01" || "http://eidas.europa.eu/LoA/high"
        ""             || "O’CONNEŽ-ŠUSLIK TESTNUMBER" || "MARY ÄNN" || "EE/CA/60001019906" || "2000-01-01" || "http://eidas.europa.eu/LoA/high"
    }

    @Unroll
    @Feature("User can cancel the authentication and return to SP")
    def "cancel authentication in IDP"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response taraLoginPageResponse = Steps.startAuthProcessFollowRedirectsToTara(flow, samlRequest)
        Response cancelResponse = Steps.userCancelAndFollowRedirects(flow, taraLoginPageResponse)

        org.opensaml.saml.saml2.core.Response samlResponseObj = SamlResponseUtils.getSamlResponseFromResponse(cancelResponse)

        assertEquals("The request could not be performed due to an error on the part of the requester.", samlStatusCode, samlResponseObj.getStatus().getStatusCode().getValue());
        assertEquals("The SAML responder or SAML authority is able to process the request but has chosen not to respond.", samlSubStatusCode, samlResponseObj.getStatus().getStatusCode().getStatusCode().getValue());
        assertEquals("Reason for unsuccessful authentication.", samlStatusMessage, samlResponseObj.getStatus().getStatusMessage().getMessage());

        where:
        samlStatusCode                                 || samlSubStatusCode                                  || samlStatusMessage
        "urn:oasis:names:tc:SAML:2.0:status:Requester" || "urn:oasis:names:tc:SAML:2.0:status:RequestDenied" || "User canceled the authentication process"
      }

    @Unroll
    @Feature("User consent")
    def "user can deny the usage of personal data"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response taraLoginPageResponse = Steps.startAuthProcessFollowRedirectsToTara(flow, samlRequest)
        Response consentPageResponse = Steps.authenticateWithMidAndFollowRedirects(flow, taraLoginPageResponse)
        Response consentDeniedResponse = Steps.userDenyConsentAndFollowRedirects(flow, consentPageResponse)

        org.opensaml.saml.saml2.core.Response samlResponseObj = SamlResponseUtils.getSamlResponseFromResponse(consentDeniedResponse)

        assertEquals("The request could not be performed due to an error on the part of the requester.", samlStatusCode, samlResponseObj.getStatus().getStatusCode().getValue());
        assertEquals("The SAML responder or SAML authority is able to process the request but has chosen not to respond.", samlSubStatusCode, samlResponseObj.getStatus().getStatusCode().getStatusCode().getValue());
        assertEquals("Reason for unsuccessful authentication.", samlStatusMessage, samlResponseObj.getStatus().getStatusMessage().getMessage());

        where:
        samlStatusCode                                 || samlSubStatusCode                                  || samlStatusMessage
        "urn:oasis:names:tc:SAML:2.0:status:Requester" || "urn:oasis:names:tc:SAML:2.0:status:RequestDenied" || "User canceled the authentication process"
      }

    @Unroll
    @Feature("Optional attributes MAY be supplied by a MS if available and acceptable to national law")
    def "request authentication with optional attributes"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithOptionalAttributes(flow, "DEMO-SP-CA")
        Response taraLoginPageResponse = Steps.startAuthProcessFollowRedirectsToTara(flow, samlRequest)
        Response consentPageResponse = Steps.authenticateWithMidAndFollowRedirects(flow, taraLoginPageResponse)
        Response authenticationResponse = Steps.userConsentAndFollowRedirects(flow, consentPageResponse)

        Assertion assertion = SamlResponseUtils.getSamlAssertionFromResponse(authenticationResponse, flow.connector.signatureCredential)

        assertEquals("Correct LOA is returned", loa_level, getLoaValue(assertion));
        assertEquals("Correct family name is returned", familyName, getAttributeValue(assertion, FN_FAMILY));
        assertEquals("Correct first name is returned", firstName, getAttributeValue(assertion, FN_FIRST));
        assertEquals("Correct id code is returned", personalNumber, getAttributeValue(assertion, FN_PNO));
        assertEquals("Correct birth date is returned", dateOfBirth, getAttributeValue(assertion, FN_DATE));
        assertEquals("Only mandatory attributes are returned", 4, assertion.getAttributeStatements().get(0).getAttributes().size())

        where:
        familyName                   || firstName     || personalNumber      || dateOfBirth  || loa_level
        "O’CONNEŽ-ŠUSLIK TESTNUMBER" || "MARY ÄNN"    || "EE/CA/60001019906" || "2000-01-01" || "http://eidas.europa.eu/LoA/high"
      }

    protected String getAttributeValue(Assertion assertion, String friendlyName) {
        for (Attribute attribute : assertion.getAttributeStatements().get(0).getAttributes()) {
            if (attribute.getFriendlyName().equals(friendlyName)) {
                XSAny attributeValue = (XSAny) attribute.getAttributeValues().get(0);
                return attributeValue.getTextContent();
            }
        }
        throw new RuntimeException("No such attribute found: " + friendlyName);
    }

    protected String getLoaValue(Assertion assertion) {
        return assertion.getAuthnStatements().get(0).getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef();
    }
}
