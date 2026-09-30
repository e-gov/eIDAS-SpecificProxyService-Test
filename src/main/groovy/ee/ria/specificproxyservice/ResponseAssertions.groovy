package ee.ria.specificproxyservice

import io.qameta.allure.Step
import io.restassured.response.Response

import static org.hamcrest.CoreMatchers.equalTo
import static org.hamcrest.MatcherAssert.assertThat

class ResponseAssertions {

    @Step("Verify security headers")
    static void assertSecurityHeaders(Response response) {
        assertThat("Correct X-Content-Type-Options", response.getHeader("X-Content-Type-Options"), equalTo("nosniff"))
        assertThat("Correct X-Frame-Options", response.getHeader("X-Frame-Options"), equalTo("DENY"))
        assertThat("Correct X-XSS-Protection", response.getHeader("X-XSS-Protection"), equalTo("1; mode=block"))
        assertThat("Correct Cache-Control", response.getHeader("Cache-Control"), equalTo("no-cache, no-store, max-age=0, must-revalidate"))
        assertThat("Correct Pragma", response.getHeader("Pragma"), equalTo("no-cache"))
        assertThat("Correct Expires", response.getHeader("Expires"), equalTo("0"))
    }
}
