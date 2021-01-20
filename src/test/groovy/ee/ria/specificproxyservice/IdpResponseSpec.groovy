package ee.ria.specificproxyservice

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.hamcrest.Matchers
import spock.lang.Unroll

import static org.junit.Assert.assertEquals


class IdpResponseSpec extends SpecificProxyServiceSpecification {

    Flow flow = new Flow(props)

    def setup() {
        flow.connector.signatureCredential = signatureCredential
        flow.connector.encryptionCredential = encryptionCredential
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("LOGIN_ENDPOINT_INPUT_VALIDATION")
    @Feature("LOGIN_ENDPOINT_LIGHTREQUEST")
    def "OIDC return state error handling"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response specificProxyResponse = Steps.startAuthProcessInEidasNode(flow, samlRequest)
        Response taraInitResponse = Steps.startAuthProcessInTara(flow, specificProxyResponse)
        Response midAuthAcceptResponse = Steps.authenticateWithMidAndFollowRedirects(flow, taraInitResponse)
        Response taraAuthenticationResponse = Steps.userConsentAndFollowRedirects(flow, midAuthAcceptResponse)

        String[] elements = taraAuthenticationResponse.getHeader("location").split('\\?|&')

        Response validateableResponse = Requests.idpResponse(flow, elements[0]+"?"+elements[1]+state)

        assertEquals("Correct status is returned", statusCode, validateableResponse.getStatusCode())
        assertEquals("Correct message is returned", message, validateableResponse.getBody().jsonPath().get("message"))
        assertEquals("Correct error is returned", error, validateableResponse.getBody().jsonPath().get("errors"))

        where:
        state                      || statusCode || message         || error
        "&state=some-random-state" || 400        || "Invalid state" || null
        ""                         || 400        || "Validation failed for object='idpCallbackRequest'. Error count: 1" || "Parameter 'state': must not be empty"
    }

    @Unroll
    @Feature("LOGIN_ENDPOINT_INPUT_VALIDATION")
    def "OIDC return code error handling"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response specificProxyResponse = Steps.startAuthProcessInEidasNode(flow, samlRequest)
        Response taraInitResponse = Steps.startAuthProcessInTara(flow, specificProxyResponse)
        Response midAuthAcceptResponse = Steps.authenticateWithMidAndFollowRedirects(flow, taraInitResponse)
        Response taraAuthenticationResponse = Steps.userConsentAndFollowRedirects(flow, midAuthAcceptResponse)

        String[] elements = taraAuthenticationResponse.getHeader("location").split('\\?|&')

        Response validateableResponse = Requests.idpResponse(flow, elements[0]+code+elements[2]+"&"+elements[3])

        assertEquals("Correct status is returned", statusCode, validateableResponse.getStatusCode())
        assertEquals("Correct message is returned", message, validateableResponse.getBody().jsonPath().get("message"))
        assertEquals("Correct error is returned", error, validateableResponse.getBody().jsonPath().get("errors"))

        where:
        code                      || statusCode || message         || error
        "?code=some-random-code&"  || 500        || "Something went wrong internally. Please consult server logs for further details." || null
        "?"                        || 400        || "Either error or code parameter is required" || null
    }

    @Unroll
    @Feature("LOGIN_ENDPOINT_INPUT_VALIDATION")
    def "OIDC return error handling on double state parameters"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response specificProxyResponse = Steps.startAuthProcessInEidasNode(flow, samlRequest)
        Response taraInitResponse = Steps.startAuthProcessInTara(flow, specificProxyResponse)
        Response midAuthAcceptResponse = Steps.authenticateWithMidAndFollowRedirects(flow, taraInitResponse)
        Response taraAuthenticationResponse = Steps.userConsentAndFollowRedirects(flow, midAuthAcceptResponse)

        String[] elements = taraAuthenticationResponse.getHeader("location").split('\\?|&')

        Response validateableResponse = Requests.idpResponse(flow, elements[0]+"?"+elements[1]+"&"+elements[2]+"&"+elements[3]+"&"+elements[3])

        assertEquals("Correct status is returned", 400, validateableResponse.getStatusCode())
        assertEquals("Correct message is returned", "Validation failed for object='idpCallbackRequest'. Error count: 1", validateableResponse.getBody().jsonPath().get("message"))
        assertEquals("Correct error is returned", "Parameter 'state': using multiple instances of parameter is not allowed", validateableResponse.getBody().jsonPath().get("errors"))
    }

    @Unroll
    @Feature("LOGIN_ENDPOINT_INPUT_VALIDATION")
    def "OIDC return error handling on double code parameters"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response specificProxyResponse = Steps.startAuthProcessInEidasNode(flow, samlRequest)
        Response taraInitResponse = Steps.startAuthProcessInTara(flow, specificProxyResponse)
        Response midAuthAcceptResponse = Steps.authenticateWithMidAndFollowRedirects(flow, taraInitResponse)
        Response taraAuthenticationResponse = Steps.userConsentAndFollowRedirects(flow, midAuthAcceptResponse)

        String[] elements = taraAuthenticationResponse.getHeader("location").split('\\?|&')

        Response validateableResponse = Requests.idpResponse(flow, elements[0]+"?"+elements[1]+"&"+elements[2]+"&"+elements[1]+"&"+elements[3])

        assertEquals("Correct status is returned", 400, validateableResponse.getStatusCode())
        assertEquals("Correct message is returned", "Validation failed for object='idpCallbackRequest'. Error count: 1", validateableResponse.getBody().jsonPath().get("message"))
        assertEquals("Correct error is returned", "Parameter 'code': using multiple instances of parameter is not allowed", validateableResponse.getBody().jsonPath().get("errors"))
    }

    @Unroll
    @Feature("LOGIN_ENDPOINT_INPUT_VALIDATION")
    def "OIDC return ignores unknown parameters"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response specificProxyResponse = Steps.startAuthProcessInEidasNode(flow, samlRequest)
        Response taraInitResponse = Steps.startAuthProcessInTara(flow, specificProxyResponse)
        Response midAuthAcceptResponse = Steps.authenticateWithMidAndFollowRedirects(flow, taraInitResponse)
        Response taraAuthenticationResponse = Steps.userConsentAndFollowRedirects(flow, midAuthAcceptResponse)

        Response validateableResponse = Requests.idpResponse(flow,  taraAuthenticationResponse.getHeader("location")+"&randomParam=someValue")

        assertEquals("Correct status is returned", 302, validateableResponse.getStatusCode())
    }

    @Unroll
    @Feature("LOGIN_ENDPOINT_INPUT_VALIDATION")
    @Feature("LOGIN_ENDPOINT_FAILED_LOGIN")
    def "OIDC returns usupported error on login"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response specificProxyResponse = Steps.startAuthProcessInEidasNode(flow, samlRequest)
        Steps.startAuthProcessInTara(flow, specificProxyResponse)
        String returnUrl = flow.specificProxyService.taraBaseUrl + "/auth/reject"+errorCode

        Response cancelResponse = Requests.backToServiceProvider(flow, returnUrl)

        assertEquals("Correct status is returned", statusCode, cancelResponse.getStatusCode())
        assertEquals("Correct message is returned", message, cancelResponse.getBody().jsonPath().get("message"))
        assertEquals("Correct error is returned", error, cancelResponse.getBody().jsonPath().get("error"))

        where:
        errorCode            || statusCode || message         || error
        "?error_code=hacked" || 400        || "authReject.errorCode: the only supported value is: 'user_cancel'" || "Bad Request"
    }

    @Unroll
    @Feature("LOGIN_ENDPOINT_INPUT_VALIDATION")
    @Feature("LOGIN_ENDPOINT_FAILED_LOGIN")
    def "OIDC returns supported error on login"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response specificProxyResponse = Steps.startAuthProcessInEidasNode(flow, samlRequest)
        Steps.startAuthProcessInTara(flow, specificProxyResponse)

        String returnUrl = flow.specificProxyService.taraBaseUrl + "/auth/reject?error_code=user_cancel"

        Response cancelResponse = Requests.backToServiceProvider(flow, returnUrl)
        String backToSpUrl = cancelResponse.then().extract().response().getHeader("location")

        String[] elements = backToSpUrl.split('\\?|&')

        Response idpResponse =  Requests.idpResponse(flow, elements[0]+"?"+errorCode+"&"+errorMessage+"&"+elements[3])

        assertEquals("Correct status is returned", statusCode, cancelResponse.getStatusCode())

        where:
        errorCode           | errorMessage                        || statusCode
        "error=user_cancel" | "error_description=User+canceled+the+login+process" || 302
        "error=user_cancel" | "error_description=other+description" || 302
    }

    @Unroll
    @Feature("LOGIN_ENDPOINT_LIGHTREQUEST")
    def "OIDC return can be used only once"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response specificProxyResponse = Steps.startAuthProcessInEidasNode(flow, samlRequest)
        Response taraInitResponse = Steps.startAuthProcessInTara(flow, specificProxyResponse)
        Response midAuthAcceptResponse = Steps.authenticateWithMidAndFollowRedirects(flow, taraInitResponse)
        Response taraAuthenticationResponse = Steps.userConsentAndFollowRedirects(flow, midAuthAcceptResponse)
        Requests.idpResponse(flow, taraAuthenticationResponse.getHeader("Location"))

        Response idpResponse = Requests.idpResponse(flow, taraAuthenticationResponse.getHeader("Location"))

        assertEquals("Correct status is returned", 400, idpResponse.getStatusCode())
        assertEquals("Correct message is returned", "Invalid state", idpResponse.getBody().jsonPath().get("message"))
    }

    @Unroll
    @Feature("LOGIN_ENDPOINT_LIGHTREQUEST")
    @Feature("SECURITY")
    def "Verify IdpResponse response header"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response specificProxyResponse = Steps.startAuthProcessInEidasNode(flow, samlRequest)
        Response taraInitResponse = Steps.startAuthProcessInTara(flow, specificProxyResponse)
        Response midAuthAcceptResponse = Steps.authenticateWithMidAndFollowRedirects(flow, taraInitResponse)
        Response taraAuthenticationResponse = Steps.userConsentAndFollowRedirects(flow, midAuthAcceptResponse)

        Response idpResponse = Requests.idpResponse(flow, taraAuthenticationResponse.getHeader("Location"))

        idpResponse.then().header("Content-Security-Policy", Matchers.is(contentSecurityPolicy))
    }
}
