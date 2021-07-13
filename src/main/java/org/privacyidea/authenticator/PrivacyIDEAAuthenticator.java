/*
 * Copyright 2021 NetKnights GmbH - micha.preusser@netknights.it
 * nils.behlen@netknights.it
 * - Modified
 *
 * Based on original code:
 *
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.privacyidea.authenticator;

import org.jboss.logging.Logger;
import org.jboss.resteasy.spi.HttpRequest;
import org.jetbrains.annotations.Nullable;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.privacyidea.PIResponse;
import org.privacyidea.RolloutInfo;
import org.privacyidea.TokenInfo;
import org.privacyidea.WebAuthn;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.privacyidea.PIConstants.PASSWORD;
import static org.privacyidea.PIConstants.TOKEN_TYPE_PUSH;
import static org.privacyidea.PIConstants.TOKEN_TYPE_WEBAUTHN;
import static org.privacyidea.authenticator.Const.AUTH_NOTE_ACCEPT_LANGUAGE;
import static org.privacyidea.authenticator.Const.AUTH_NOTE_AUTH_COUNTER;
import static org.privacyidea.authenticator.Const.AUTH_NOTE_TRANSACTION_ID;
import static org.privacyidea.authenticator.Const.DEFAULT_OTP_MESSAGE_DE;
import static org.privacyidea.authenticator.Const.DEFAULT_OTP_MESSAGE_EN;
import static org.privacyidea.authenticator.Const.DEFAULT_PUSH_MESSAGE_DE;
import static org.privacyidea.authenticator.Const.DEFAULT_PUSH_MESSAGE_EN;
import static org.privacyidea.authenticator.Const.FORM_FILE_NAME;
import static org.privacyidea.authenticator.Const.FORM_MODE;
import static org.privacyidea.authenticator.Const.FORM_MODE_CHANGED;
import static org.privacyidea.authenticator.Const.FORM_OTP;
import static org.privacyidea.authenticator.Const.FORM_OTP_AVAILABLE;
import static org.privacyidea.authenticator.Const.FORM_OTP_MESSAGE;
import static org.privacyidea.authenticator.Const.FORM_POLL_INTERVAL;
import static org.privacyidea.authenticator.Const.FORM_PUSH_AVAILABLE;
import static org.privacyidea.authenticator.Const.FORM_PUSH_MESSAGE;
import static org.privacyidea.authenticator.Const.FORM_TOKEN_ENROLLMENT_QR;
import static org.privacyidea.authenticator.Const.FORM_UI_LANGUAGE;
import static org.privacyidea.authenticator.Const.FORM_WEBAUTHN_ORIGIN;
import static org.privacyidea.authenticator.Const.FORM_WEBAUTHN_SIGN_REQUEST;
import static org.privacyidea.authenticator.Const.FORM_WEBAUTHN_SIGN_RESPONSE;
import static org.privacyidea.authenticator.Const.HEADER_ACCEPT_LANGUAGE;
import static org.privacyidea.authenticator.Const.TRUE;

public class PrivacyIDEAAuthenticator implements org.keycloak.authentication.Authenticator {

    private final Logger logger = Logger.getLogger(PrivacyIDEAAuthenticator.class);

    /**
     * This function will be called when the authentication flow triggers the privacyIDEA execution.
     * i.e. after the username + password have been submitted.
     *
     * @param context AuthenticationFlowContext
     */
    @Override
    public void authenticate(AuthenticationFlowContext context) {

        PrivacyIdeaClient privacyIdeaClient = PrivacyIdeaClient.createClient(context.getAuthenticatorConfig().getConfig());
        Configuration config = privacyIdeaClient.getConfig();

        // Get the things that were submitted in the first username+password form
        UserModel user = context.getUser();

        if (isUserMemberOfExcludedGroup(context, config, user)){
            context.success();
            return;
        }

        // Get the language from the request headers to pass it to the ui and the privacyIDEA requests
        String acceptLanguage = context.getSession().getContext().getRequestHeaders().getRequestHeaders().get(HEADER_ACCEPT_LANGUAGE).get(0);
        String uiLanguage = "en";
        Map<String, String> languageHeader = new LinkedHashMap<>();
        if (acceptLanguage != null) {
            languageHeader.put(HEADER_ACCEPT_LANGUAGE, acceptLanguage);
            if (acceptLanguage.toLowerCase().startsWith("de")) {
                uiLanguage = "de";
            }
        }

        // Prepare for possibly triggering challenges
        PIResponse triggerResponse = null;
        String transactionID = null;
        String pushMessage = uiLanguage.equals("en") ? DEFAULT_PUSH_MESSAGE_EN : DEFAULT_PUSH_MESSAGE_DE;
        String otpMessage = uiLanguage.equals("en") ? DEFAULT_OTP_MESSAGE_EN : DEFAULT_OTP_MESSAGE_DE;

        String currentUser = user.getUsername();
        String currentPassword = extractCurrentPasswordFromRequest(context.getHttpRequest());

        // Trigger challenges if configured. Service account has precedence over send password
        if (config.triggerChallenge()) {
            triggerResponse = privacyIdeaClient.triggerChallenges(currentUser, languageHeader);
        } else if (config.sendPassword()) {
            if (currentPassword != null) {
                triggerResponse = privacyIdeaClient.validateCheck(currentUser, currentPassword, null, languageHeader);
            } else {
                logger.warn("Cannot send password because it is null!");
            }
        }

        // Variables to configure the UI
        boolean pushAvailable = false;

        String startingMode = "otp";
        String webAuthnSignRequest = "";

        // Evaluate for possibly triggered token
        if (triggerResponse != null) {
            transactionID = triggerResponse.transactionID;

            if (!triggerResponse.multiChallenge().isEmpty()) {
                pushAvailable = triggerResponse.pushAvailable();
                if (pushAvailable) {
                    pushMessage = triggerResponse.pushMessage();
                }

                otpMessage = triggerResponse.otpMessage();

                // Check for WebAuthnSignRequest
                // TODO currently only gets the first sign request
                if (triggerResponse.triggeredTokenTypes().contains(TOKEN_TYPE_WEBAUTHN)) {
                    List<WebAuthn> signRequests = triggerResponse.webAuthnSignRequests();
                    if (!signRequests.isEmpty()) {
                        webAuthnSignRequest = signRequests.get(0).signRequest();
                    }
                }
            }

            // Check if any triggered token matches the preferred token type
            if (triggerResponse.triggeredTokenTypes().contains(config.prefTokenType())) {
                startingMode = config.prefTokenType();
            }
        }

        // Enroll token if enabled and user does not have one. If something was triggered before, don't even try.
        String tokenEnrollmentQR = "";
        if (config.enrollToken() && (transactionID == null || transactionID.isEmpty())) {
            List<TokenInfo> tokenInfos = privacyIdeaClient.getTokenInfo(currentUser);

            if (tokenInfos == null || tokenInfos.isEmpty()) {
                RolloutInfo rolloutInfo = privacyIdeaClient.tokenRollout(currentUser, config.enrollingTokenType());
                tokenEnrollmentQR = rolloutInfo.googleurl.img;
            }
        }

        // Prepare the form and auth notes to pass infos to the UI or the next step
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        authSession.setAuthNote(AUTH_NOTE_AUTH_COUNTER, "0");
        authSession.setAuthNote(AUTH_NOTE_ACCEPT_LANGUAGE, acceptLanguage);

        if (transactionID != null && !transactionID.isEmpty()) {
            authSession.setAuthNote(AUTH_NOTE_TRANSACTION_ID, transactionID);
        }

        boolean otpAvailable = true; // Always assume an OTP token

        Response responseForm = context.form()
                .setAttribute(FORM_POLL_INTERVAL, config.pollingInterval().get(0))
                .setAttribute(FORM_TOKEN_ENROLLMENT_QR, tokenEnrollmentQR)
                .setAttribute(FORM_MODE, startingMode)
                .setAttribute(FORM_PUSH_AVAILABLE, pushAvailable)
                .setAttribute(FORM_OTP_AVAILABLE, otpAvailable)
                .setAttribute(FORM_PUSH_MESSAGE, pushMessage.toString())
                .setAttribute(FORM_OTP_MESSAGE, otpMessage.toString())
                .setAttribute(FORM_WEBAUTHN_SIGN_REQUEST, webAuthnSignRequest)
                .setAttribute(FORM_UI_LANGUAGE, uiLanguage)
                .createForm(FORM_FILE_NAME);
        context.challenge(responseForm);
    }

    @Nullable
    private String extractCurrentPasswordFromRequest(HttpRequest request) {
        //log("[authenticate] http form params: " + context.getHttpRequest().getDecodedFormParameters().toString());
        return request.getDecodedFormParameters().getFirst(PASSWORD);
    }

    private boolean isUserMemberOfExcludedGroup(AuthenticationFlowContext context, Configuration config, UserModel user) {
        // Check if the current user is member of an excluded group
        for (GroupModel groupModel : user.getGroups()) {
            if (config.excludedGroups().contains(groupModel.getName())) {
                return true;
            }
        }
        return false;
    }

    /**
     * This function will be called when our form is submitted.
     *
     * @param context AuthenticationFlowContext
     */
    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel")) {
            context.cancelLogin();
            return;
        }
        LoginFormsProvider form = context.form();

        //logger.info("formData:");
        //formData.forEach((k, v) -> logger.info("key=" + k + ", value=" + v));

        // Get data from form
        String tokenEnrollmentQR = formData.getFirst(FORM_TOKEN_ENROLLMENT_QR);
        String currentMode = formData.getFirst(FORM_MODE);
        boolean pushToken = TRUE.equals(formData.getFirst(FORM_PUSH_AVAILABLE));
        boolean otpToken = TRUE.equals(formData.getFirst(FORM_OTP_AVAILABLE));
        String pushMessage = formData.getFirst(FORM_PUSH_MESSAGE);
        String otpMessage = formData.getFirst(FORM_OTP_MESSAGE);
        String tokenTypeChanged = formData.getFirst(FORM_MODE_CHANGED);
        String uiLanguage = formData.getFirst(FORM_UI_LANGUAGE);
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String transactionID = authSession.getAuthNote(AUTH_NOTE_TRANSACTION_ID);
        String currentUserName = context.getUser().getUsername();

        // Reuse the accept language for any requests made in this step
        String acceptLanguage = authSession.getAuthNote(AUTH_NOTE_ACCEPT_LANGUAGE);
        Map<String, String> languageHeader = Collections.singletonMap(HEADER_ACCEPT_LANGUAGE, acceptLanguage);

        String webAuthnSignRequest = formData.getFirst(FORM_WEBAUTHN_SIGN_REQUEST);
        String webAuthnSignResponse = formData.getFirst(FORM_WEBAUTHN_SIGN_RESPONSE);
        // The origin is set by the form every time, no need to put it in the form again
        String origin = formData.getFirst(FORM_WEBAUTHN_ORIGIN);

        // Prepare the failure message, the message from privacyIDEA will be appended if possible
        String authenticationFailureMessage = "Authentication failed.";

        // Set the "old" values again
        form.setAttribute(FORM_TOKEN_ENROLLMENT_QR, tokenEnrollmentQR)
                .setAttribute(FORM_MODE, currentMode)
                .setAttribute(FORM_PUSH_AVAILABLE, pushToken)
                .setAttribute(FORM_OTP_AVAILABLE, otpToken)
                .setAttribute(FORM_WEBAUTHN_SIGN_REQUEST, webAuthnSignRequest)
                .setAttribute(FORM_UI_LANGUAGE, uiLanguage);

        boolean didTrigger = false; // To not show the error message if something was triggered
        PIResponse response = null;

        PrivacyIdeaClient privacyIdeaClient = PrivacyIdeaClient.createClient(context.getAuthenticatorConfig().getConfig());
        Configuration config = privacyIdeaClient.getConfig();

        // Determine to which endpoint we send the data from the form based on the mode the form was in
        // Or if a WebAuthnSignResponse is present
        if (TOKEN_TYPE_PUSH.equals(currentMode)) {
            // In push mode, we poll for the transaction id to see if the challenge has been answered
            if (privacyIdeaClient.pollTransaction(transactionID)) {
                // If the challenge has been answered, finalize with a call to validate check
                response = privacyIdeaClient.validateCheck(currentUserName, "", transactionID, languageHeader);
            }
        } else if (webAuthnSignResponse != null && !webAuthnSignResponse.isEmpty()) {
            if (origin == null || origin.isEmpty()) {
                logger.error("Origin is missing for WebAuthn authentication!");
            } else {
                response = privacyIdeaClient.validateCheckWebAuthn(currentUserName, transactionID, webAuthnSignResponse, origin, languageHeader);
            }
        } else {
            if (!(TRUE.equals(tokenTypeChanged))) {
                String otp = formData.getFirst(FORM_OTP);
                // If the transaction id is not present, it will be not be added in validateCheck, so no need to check here
                response = privacyIdeaClient.validateCheck(currentUserName, otp, transactionID, languageHeader);
            }
        }

        // Evaluate the response
        if (response != null) {
            // On success we finish our execution
            if (response.value) {
                context.success();
                return;
            }

            // If the authentication was not successful (yet), either the provided data was wrong
            // or another challenge was triggered
            if (!response.multiChallenge().isEmpty()) {
                // A challenge was triggered, display its message and save the transaction id in the session
                otpMessage = response.message;
                authSession.setAuthNote(AUTH_NOTE_TRANSACTION_ID, response.transactionID);
                didTrigger = true;
            } else {
                // The authentication failed without triggering anything so the things that have been sent before were wrong
                authenticationFailureMessage += "\n" + response.message;
            }
        }

        // The authCounter is also used to determine the polling interval for push
        // If the authCounter is bigger than the size of the polling interval list, repeat the lists last value
        int authCounter = Integer.parseInt(authSession.getAuthNote(AUTH_NOTE_AUTH_COUNTER)) + 1;
        authCounter = authCounter >= config.pollingInterval().size() ? config.pollingInterval().size() - 1 : authCounter;
        authSession.setAuthNote(AUTH_NOTE_AUTH_COUNTER, Integer.toString(authCounter));

        // The message variables could be overwritten if a challenge was triggered. Therefore, add them here at the end
        form.setAttribute(FORM_POLL_INTERVAL, config.pollingInterval().get(authCounter))
                .setAttribute(FORM_PUSH_MESSAGE, (pushMessage == null ? DEFAULT_PUSH_MESSAGE_EN : pushMessage))
                .setAttribute(FORM_OTP_MESSAGE, (otpMessage == null ? DEFAULT_OTP_MESSAGE_EN : otpMessage));

        // Do not display the error if the token type was switched or if another challenge was triggered
        if (!(TRUE.equals(tokenTypeChanged)) && !didTrigger) {
            form.setError(TOKEN_TYPE_PUSH.equals(currentMode) ? "Authentication not verified yet." : authenticationFailureMessage);
        }

        Response responseForm = form.createForm(FORM_FILE_NAME);
        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, responseForm);
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}
