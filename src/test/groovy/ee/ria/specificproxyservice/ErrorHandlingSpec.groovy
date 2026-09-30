package ee.ria.specificproxyservice

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.apache.http.HttpStatus

import static ee.ria.specificproxyservice.ResponseAssertions.assertSecurityHeaders
import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.containsString
import static org.hamcrest.Matchers.endsWith
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.not
import static org.hamcrest.Matchers.notNullValue
import static org.hamcrest.Matchers.startsWith

class ErrorHandlingSpec extends SpecificProxyServiceSpecification {

    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Feature("PROCESS_ERRORS")
    def "disallowed HTTP method returns the error envelope"() {
        expect:
        Response response = Requests.request(flow, "PUT", flow.specificProxyService.fullheartbeatUrl)

        assertThat("Correct HTTP status code is returned", response.statusCode(),
                equalTo(HttpStatus.SC_METHOD_NOT_ALLOWED))
        assertThat("Correct status in body", response.body().jsonPath().getInt("status"),
                equalTo(HttpStatus.SC_METHOD_NOT_ALLOWED))
        assertThat("Correct error", response.body().jsonPath().getString("error"),
                equalTo("Method Not Allowed"))
        assertThat("Correct message", response.body().jsonPath().getString("message"),
                equalTo("Request method 'PUT' not supported"))
        assertThat("Correct path", response.body().jsonPath().getString("path"),
                endsWith(flow.specificProxyService.heartbeatUrl))
        assertThat("Incident number is present", response.body().jsonPath().get("incidentNumber"),
                notNullValue())
        assertSecurityHeaders(response)
    }

    @Feature("PROCESS_ERRORS")
    def "browser reaching the error page gets the branded page, not Whitelabel"() {
        expect:
        Response response = Requests.request(flow, "GET", flow.specificProxyService.fullheartbeatUrl + ";",
                ["Accept": "text/html"])

        assertThat("Correct HTTP status code is returned", response.statusCode(),
                equalTo(HttpStatus.SC_BAD_REQUEST))
        assertThat("Correct content type", response.getContentType(), startsWith("text/html"))
        assertThat("Whitelabel page is not served", response.body().asString(),
                not(containsString("Whitelabel Error Page")))
        assertThat("Branded error page is served",
                response.body().htmlPath().getString("**.find {it.@id == 'error'}"),
                equalTo("Bad Request"))
    }
}
