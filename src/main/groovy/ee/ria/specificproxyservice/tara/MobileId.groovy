package ee.ria.specificproxyservice.tara


import ee.ria.specificproxyservice.Flow
import io.qameta.allure.Step
import io.qameta.allure.restassured.AllureRestAssured
import io.restassured.RestAssured
import io.restassured.response.Response
import org.joda.time.DateTime

import static io.restassured.RestAssured.given
import static io.restassured.config.EncoderConfig.encoderConfig
import static org.junit.Assert.assertEquals

class MobileId {
    @Step("Authenticates with Mobile-ID")
    static Response authenticateWithMobileId(Flow flow, Response taraLoginPageResponse, String mobileNo, String idCode, Integer pollMillis) throws InterruptedException, URISyntaxException, IOException {
        String midInitUrl = taraLoginPageResponse.getBody().htmlPath().getString("**.findAll { it.@id == 'mobileIdForm' }.@action")
        Response submitResponse = submitMobileIdLogin(flow, mobileNo, idCode, flow.specificProxyService.taraBaseUrl + midInitUrl)
        assertEquals("Correct HTTP status code is returned", 200, submitResponse.statusCode())
        Response pollResponse = pollForAuthentication(flow, flow.specificProxyService.taraBaseUrl + "/auth/mid/poll", pollMillis)
        assertEquals("Correct HTTP status code is returned", 200, pollResponse.statusCode())

        return pollResponse
    }


    @Step("Submit Mobile-ID login")
    static Response submitMobileIdLogin(Flow flow, String mobileNo, String idCode, String location) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .cookie("SESSION", flow.sessionId)
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                .formParam("idCode", idCode)
                .formParam("telephoneNumber", mobileNo)
                .formParam("_csrf", flow.csrf)
                .when()
                .post(location)
                .then()
                .extract().response()
    }

    @Step("Poll Mobile-ID authentication")
    static Response pollForAuthentication(Flow flow, String location, Integer intervalMillis) throws InterruptedException {
        DateTime endTime = new DateTime().plusMillis(intervalMillis * 4 + 200)
        while (new DateTime().isBefore(endTime)) {
            Thread.sleep(intervalMillis)
            Response response = given()
                    .filter(flow.getCookieFilter())
                    .filter(new AllureRestAssured())
                    .cookie("SESSION", flow.sessionId)
                    .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                    .redirects().follow(false)
                    .when()
                    .get(location)
                    .then()
                    .extract().response()
            if( response.body().jsonPath().get("status") != "PENDING") {
                return response
            }
        }
        throw new RuntimeException("No MID response in: " + (intervalMillis * 4 + 200) + " millis")
    }
}
