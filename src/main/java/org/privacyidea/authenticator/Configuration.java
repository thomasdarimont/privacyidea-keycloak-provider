/*
 * Copyright 2021 NetKnights GmbH - nils.behlen@netknights.it
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.privacyidea.PIConstants.TOKEN_TYPE_OTP;
import static org.privacyidea.authenticator.Const.CONFIG_DO_LOG;
import static org.privacyidea.authenticator.Const.CONFIG_ENROLL_TOKEN;
import static org.privacyidea.authenticator.Const.CONFIG_ENROLL_TOKENTYPE;
import static org.privacyidea.authenticator.Const.CONFIG_EXCLUDED_GROUPS;
import static org.privacyidea.authenticator.Const.CONFIG_PREF_TOKENTYPE;
import static org.privacyidea.authenticator.Const.CONFIG_PUSH_INTERVAL;
import static org.privacyidea.authenticator.Const.CONFIG_REALM;
import static org.privacyidea.authenticator.Const.CONFIG_SEND_PASSWORD;
import static org.privacyidea.authenticator.Const.CONFIG_SERVER;
import static org.privacyidea.authenticator.Const.CONFIG_SERVICE_ACCOUNT;
import static org.privacyidea.authenticator.Const.CONFIG_SERVICE_PASS;
import static org.privacyidea.authenticator.Const.CONFIG_SERVICE_REALM;
import static org.privacyidea.authenticator.Const.CONFIG_TRIGGER_CHALLENGE;
import static org.privacyidea.authenticator.Const.CONFIG_VERIFY_SSL;
import static org.privacyidea.authenticator.Const.DEFAULT_POLLING_ARRAY;
import static org.privacyidea.authenticator.Const.DEFAULT_POLLING_INTERVAL;
import static org.privacyidea.authenticator.Const.TRUE;
import static org.privacyidea.authenticator.Const.FALSE;

class Configuration {

    private final String serverURL;
    private final String realm;
    private final boolean doSSLVerify;
    private final boolean doTriggerChallenge;
    private final boolean doSendPassword;

    private final String serviceAccountName;
    private final String serviceAccountPass;
    private final String serviceAccountRealm;
    private final List<String> excludedGroups = new ArrayList<>();
    private final boolean doEnrollToken;
    private final boolean doLog;
    private final String enrollingTokenType;
    private final List<Integer> pollingInterval = new ArrayList<>();
    private final String prefTokenType;

    Configuration(Map<String, String> configMap) {
        this.serverURL = configMap.get(CONFIG_SERVER);
        this.realm = configMap.getOrDefault(CONFIG_REALM, "");
        this.doSSLVerify = configMap.getOrDefault(CONFIG_VERIFY_SSL, FALSE).equals(TRUE);
        this.doTriggerChallenge = configMap.getOrDefault(CONFIG_TRIGGER_CHALLENGE, FALSE).equals(TRUE);
        this.serviceAccountName = configMap.getOrDefault(CONFIG_SERVICE_ACCOUNT, "");
        this.serviceAccountPass = configMap.getOrDefault(CONFIG_SERVICE_PASS, "");
        this.serviceAccountRealm = configMap.getOrDefault(CONFIG_SERVICE_REALM, "");

        this.doEnrollToken = configMap.getOrDefault(CONFIG_ENROLL_TOKEN, FALSE).equals(TRUE);
        this.doSendPassword = configMap.getOrDefault(CONFIG_SEND_PASSWORD, FALSE).equals(TRUE);
        // PI uses all lowercase letters for token types so change it here to match it internally
        this.prefTokenType = configMap.getOrDefault(CONFIG_PREF_TOKENTYPE, TOKEN_TYPE_OTP).toLowerCase();
        this.enrollingTokenType = configMap.getOrDefault(CONFIG_ENROLL_TOKENTYPE, "").toLowerCase();

        this.doLog = configMap.getOrDefault(CONFIG_DO_LOG, FALSE).equals(TRUE);

        String excludedGroupsStr = configMap.get(CONFIG_EXCLUDED_GROUPS);
        if (excludedGroupsStr != null) {
            this.excludedGroups.addAll(Arrays.asList(excludedGroupsStr.split(",")));
        }

        // Set intervals to either default or configured values
        String s = configMap.get(CONFIG_PUSH_INTERVAL);
        if (s == null) {
            this.pollingInterval.addAll(DEFAULT_POLLING_ARRAY);
            return;
        }

        List<String> strPollingIntervals = Arrays.asList(s.split(","));
        if (strPollingIntervals.isEmpty()) {
            return;
        }

        this.pollingInterval.clear();
        for (String str : strPollingIntervals) {
            try {
                this.pollingInterval.add(Integer.parseInt(str));
            } catch (NumberFormatException e) {
                this.pollingInterval.add(DEFAULT_POLLING_INTERVAL);
            }
        }
    }

    String serverURL() {
        return serverURL;
    }

    String realm() {
        return realm;
    }

    boolean sslVerify() {
        return doSSLVerify;
    }

    boolean triggerChallenge() {
        return doTriggerChallenge;
    }

    String serviceAccountName() {
        return serviceAccountName;
    }

    String serviceAccountPass() {
        return serviceAccountPass;
    }

    String serviceAccountRealm() {
        return serviceAccountRealm;
    }

    List<String> excludedGroups() {
        return excludedGroups;
    }

    boolean enrollToken() {
        return doEnrollToken;
    }

    String enrollingTokenType() {
        return enrollingTokenType;
    }

    List<Integer> pollingInterval() {
        return pollingInterval;
    }

    boolean doLog() {
        return doLog;
    }

    boolean sendPassword() {
        return doSendPassword;
    }

    String prefTokenType() {
        return prefTokenType;
    }
}
