package ee.ria.specificproxyservice

import io.qameta.allure.Step
import io.qameta.allure.restassured.AllureRestAssured
import io.restassured.RestAssured
import io.restassured.response.Response

import static io.restassured.RestAssured.config
import static io.restassured.RestAssured.given
import static io.restassured.config.EncoderConfig.encoderConfig

class Requests {
    @Step("Get metadata")
    static String getMetadataBody(Flow flow) {
        return given()
                .config(config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .relaxedHTTPSValidation()
                .filter(new AllureRestAssured())
                .when()
                .get(flow.specificProxyService.fullMetadataUrl)
                .then()
                .statusCode(200)
                .extract().body().asString()
    }

    @Step("Open authentication page")
    static Response getAuthenticationPage(Flow flow, String samlRequest) {
        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .formParam("SAMLRequest", samlRequest)
                        .formParam("RelayState", "")
                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .post(flow.specificProxyService.fullAuthenticationRequestUrl)
                        .then()
                        .extract().response()
        return response
    }

    @Step("Proxy Service Request")
    static Response proxyServiceRequest(Flow flow, String action, String token) {
        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .formParam("token", token)

                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .post(action)
                        .then()
                        .extract().response()
        return response
    }

    @Step("TARA OpenID Connect Autentication Request")
    public static Response followRedirect(Flow flow, String location) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .relaxedHTTPSValidation()
                .when()
                .redirects().follow(false)
                .urlEncodingEnabled(false)
                .get(location)
                .then()
                .extract().response();
    }

    @Step("{flow.endUser}Follow OpenID Connect Autentication request redirect")
    public static Response followTARARedirect(Flow flow, String location) {
        return given()
                .filter(flow.getCookieFilter())
                .filter(new AllureRestAssured())
                .relaxedHTTPSValidation()
                .when()
                .redirects().follow(false)
                .urlEncodingEnabled(false)
                .get(location)
                .then()
                .extract().response();
    }
    @Step("Consent Submit")
    static Response consentSubmit(Flow flow, String token) {
        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .queryParam("token", token)

                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .redirects().follow(false)
                        .get(flow.specificProxyService.fullConsentUrl)
                        .then()
                        .extract().response()
        return response
    }
}
