/**
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE and NOTICE files at the root of the source
 * tree and available online at
 *
 * http://www.dspace.org/license/
 */
package org.dspace.authenticate.clarin;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.dspace.authenticate.AuthenticationMethod;
import org.dspace.authenticate.ShibAuthentication;
import org.dspace.authenticate.factory.AuthenticateServiceFactory;
import org.dspace.core.Context;
import org.dspace.eperson.EPerson;
import org.dspace.eperson.Group;
import org.dspace.eperson.service.EPersonService;

/**
 * CLARIN migration authentication: reuse only an existing qualified federated identity.
 *
 * Email, Remote-User and verification tokens never establish an account link. Unknown
 * identities require review; login does not create accounts, change profile/NetID,
 * registrations, passwords or explicit group memberships. The existing canLogIn flag
 * retains its legacy password-login meaning for institutional accounts.
 */
public class ClarinShibAuthentication extends ShibAuthentication {
    public static final String ACCOUNT_REVIEW_REQUIRED = "shib.account-review-required";
    private static final Logger log = LogManager.getLogger(ClarinShibAuthentication.class);

    @Override
    public int authenticate(Context context, String username, String password,
                            String realm, HttpServletRequest request) throws SQLException {
        // Explicit credentials belong to the independently configured password provider.
        if (request == null || StringUtils.isNotEmpty(username) || StringUtils.isNotEmpty(password)) {
            return BAD_ARGS;
        }
        request.removeAttribute("shib.authenticated");
        request.removeAttribute(ACCOUNT_REVIEW_REQUIRED);
        // The old email-verification protocol is not a substitute for a fresh SP session.
        if (request.getHeader("verification-token") != null || request.getParameter("verification-token") != null
                || request.getAttribute("shib.headers") != null) {
            return BAD_ARGS;
        }
        ShibHeaders headers = new ShibHeaders(request);
        EPerson person = findEpersonByNetId(headers.getNetIdHeaders(), headers, ePersonService, context, false);
        if (person == null) {
            request.setAttribute(ACCOUNT_REVIEW_REQUIRED, true);
            return NO_SUCH_USER;
        }
        // No mutable user state is retained on this singleton provider.
        context.setCurrentUser(person);
        request.setAttribute("shib.authenticated", true);
        return SUCCESS;
    }

    /**
     * Resolve all supplied identifiers without selecting one arbitrarily when they disagree.
     * The legacy logAllowed parameter is retained for source compatibility; values are never logged.
     */
    public static EPerson findEpersonByNetId(String[] netidHeaders, ShibHeaders headers,
                                            EPersonService people, Context context, boolean logAllowed)
            throws SQLException {
        List<String> issuers = headers.get("Shib-Identity-Provider");
        if (netidHeaders == null || issuers == null || issuers.size() != 1
                || StringUtils.isBlank(issuers.get(0))) {
            return null;
        }
        EPerson match = null;
        for (String header : netidHeaders) {
            List<String> identifiers = headers.get(header.trim());
            if (identifiers == null) {
                continue;
            }
            if (identifiers.size() != 1 || StringUtils.isBlank(identifiers.get(0))) {
                return null;
            }
            // get_single preserves the production identifier[IdP] representation.
            EPerson candidate = people.findByNetid(context, headers.get_single(header.trim()));
            if (candidate != null) {
                if (match != null && !match.getID().equals(candidate.getID())) {
                    return null;
                }
                match = candidate;
            }
        }
        return match;
    }

    @Override
    public String loginPageURL(Context context, HttpServletRequest request, HttpServletResponse response) {
        String ui = configurationService.getProperty("dspace.ui.url");
        String callback = configurationService.getProperty("dspace.server.url") + "/api/authn/shibboleth"
                + "?redirectUrl=" + URLEncoder.encode(ui, StandardCharsets.UTF_8);
        String initiator = configurationService.getProperty("authentication-shibboleth.lazysession.loginurl");
        if (StringUtils.isBlank(initiator)) {
            return null;
        }
        return response.encodeRedirectURL(initiator + "?target=" + URLEncoder.encode(callback, StandardCharsets.UTF_8));
    }

    public static boolean isEnabled() {
        Iterator<AuthenticationMethod> methods = AuthenticateServiceFactory.getInstance()
                .getAuthenticationService().authenticationMethodIterator();
        while (methods.hasNext()) {
            if (methods.next() instanceof ClarinShibAuthentication) {
                return true;
            }
        }
        return false;
    }

    @Override
    public List<Group> getSpecialGroups(Context context, HttpServletRequest request) {
        try {
            // User has not successfully authenticated via shibboleth.
            if (request == null || context.getCurrentUser() == null) {
                return Collections.emptyList();
            }

            List<Group> specialGroups = context.getSpecialGroups();
            if (!specialGroups.isEmpty()) {
                log.debug("Returning special groups from context.");
                return specialGroups;
            }

            if (request.getAttribute("shib.authenticated") == null) {
                log.debug("User has not been authenticated via shibboleth, returning empty list of special groups.");
                return Collections.emptyList();
            }

            List<UUID> groupIds = new ShibGroup(new ShibHeaders(request), context).get();

            List<Group> groups = new ArrayList<>();
            for (UUID uuid : groupIds) {
                Group foundGroup = groupService.find(context, uuid);
                if (foundGroup != null) {
                    groups.add(foundGroup);
                }
            }
            return groups;
        } catch (Throwable t) {
            log.error("Unable to validate Shibboleth special groups.");
            return Collections.emptyList();
        }
    }


    /** Retained for callers outside the login path; never used as an account key. */
    public static String sortEmailsAndGetFirst(String value) {
        List<String> emails = Arrays.stream(value.split("(?<!\\\\);"))
                .map(email -> email.replaceAll("\\\\;", ";")).collect(Collectors.toList());
        emails.sort(String::compareToIgnoreCase);
        return emails.get(0);
    }
}
