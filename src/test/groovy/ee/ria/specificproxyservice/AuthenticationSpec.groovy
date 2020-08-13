package ee.ria.specificproxyservice

import ee.ria.specificproxyservice.tara.MobileId
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.opensaml.saml.saml2.core.Assertion

import java.nio.charset.StandardCharsets

class AuthenticationSpec extends SpecificProxyServiceSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.connector.signatureCredential = signatureCredential
        flow.cookieFilter = new CookieFilter()
    }

    def "authentication"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithDefault(flow);
        Response response1 = Requests.getAuthenticationPage(flow, samlRequest)

        String action = response1.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.@action")
        String token = response1.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.input[0].@value")

        Response response2 = Requests.proxyServiceRequest(flow, action, token)
        response2.then().statusCode(302)

        String taraUrl = response2.then().extract().response().getHeader("location")

        Response response3 = MobileId.authenticateWithMobileId(flow, taraUrl, "00000766", "60001019906", 7000)
        String location = response3.then().extract().response()
                .getHeader("location");

        //TODO: different step
        Response response4 = Requests.followRedirect(flow, location)
        //TODO: if consent is disabled
        //String consentAction = response4.body().htmlPath().get("**.find {it.@id == 'consentSelector'}.@action")
        String consentToken = response4.body().htmlPath().get("**.find {it.@id == 'consentSelector'}.input[0].@value")

        Response response5 = Requests.consentSubmit(flow, consentToken)
        String location2 = response5.then().extract().response()
                .getHeader("location")
        Response response6 = Requests.followRedirect(flow, location2)

        String samlResponse = response6.getBody().htmlPath().getString("**.findAll { it.@name == 'SAMLResponse' }[0].@value");
        String decodedSamlResponse = new String(Base64.getDecoder().decode(samlResponse), StandardCharsets.UTF_8);
        SamlSigantureUtils.validateSamlResponseSignature(decodedSamlResponse);
        org.opensaml.saml.saml2.core.Response samlResponseObj = OpenSAMLUtils.getSamlResponse(decodedSamlResponse);
        Assertion assertion = SamlSigantureUtils.decryptAssertion(samlResponseObj.getEncryptedAssertions().get(0), flow.connector.signatureCredential);
        assertion.getAuthnStatements().get(0).getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef();
    }
}
