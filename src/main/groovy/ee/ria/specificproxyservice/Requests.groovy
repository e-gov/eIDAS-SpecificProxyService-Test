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

    @Step("Get heartbeat")
    static Response getHeartbeat(Flow flow) {
        return given()
                .config(config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .relaxedHTTPSValidation()
                .filter(new AllureRestAssured())
                .when()
                .get(flow.specificProxyService.fullheartbeatUrl)
                .then()
                .statusCode(200)
                .extract().response()
    }

    @Step("POST to colleagueRequest")
    static Response colleagueRequest(Flow flow, String samlRequest) {
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

    @Step("GET to idpResponse")
    static Response idpResponse(Flow flow, String url) {
        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .redirects().follow(false)
                        .get(url)
                        .then()
                        .extract().response()
        return response
    }

    @Step("GET to specificProxyResponse")
    static Response specificProxyResponse(Flow flow, String url) {
        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .get(url)
                        .then()
                        .extract().response()
        return response
    }

    @Step("POST to proxyServiceRequest")
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

    @Step("Follow redirect")
    static Response followRedirect(Flow flow, String location) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .relaxedHTTPSValidation()
                .when()
                .redirects().follow(false)
                .urlEncodingEnabled(false)
                .get(location)
                .then()
                .extract().response()
    }

    @Step("Follow redirect with CSRF cookies")
    static Response followRedirectWithCsrfCookie(Flow flow, String location) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .cookie("oauth2_authentication_csrf", flow.oauth2_authentication_csrf)
                .cookie("oauth2_consent_csrf", flow.oauth2_consent_csrf)
                .relaxedHTTPSValidation()
                .when()
                .redirects().follow(false)
                .urlEncodingEnabled(false)
                .get(location)
                .then()
                .extract().response()
    }

    @Step("Start TARA authentication flow")
    static Response startAuthenticationFlowInTara(Flow flow, String location) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .cookie("oauth2_authentication_csrf", flow.oauth2_authentication_csrf)
                .relaxedHTTPSValidation()
                .when()
                .redirects().follow(false)
                .urlEncodingEnabled(false)
                .get(location)
                .then()
                .extract().response()
    }

    @Step("Start user consent flow")
    static Response startConsentFlow(Flow flow, String url) {
        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .cookie("SESSION", flow.sessionId)
                        .formParam("_csrf", flow.csrf)
                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .redirects().follow(false)
                        .post(url)
                        .then().log().cookies()
                        .extract().response()
        return response
    }

    @Step("Consent Submit")
    static Response consentSubmit(Flow flow, String url, Boolean consentGiven) {
        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .queryParam("consent_given", consentGiven)
                        .cookie("SESSION", flow.sessionId)
                        .formParam("_csrf", flow.csrf)
                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .redirects().follow(false)
                        .post(url)
                        .then().log().cookies()
                        .extract().response()
        return response
    }

    @Step("Return to service provider without authentication")
    static Response backToServiceProvider(Flow flow, String url) {
        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .redirects().follow(false)
                        .get(url)
                        .then()
                        .extract().response()
        return response
    }
}
