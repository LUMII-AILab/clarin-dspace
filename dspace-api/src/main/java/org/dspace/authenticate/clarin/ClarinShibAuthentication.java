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
import java.util.Locale;
import java.util.UUID;
import java.util.stream.Collectors;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.dspace.app.util.Util;
import org.dspace.authenticate.AuthenticationMethod;
import org.dspace.authenticate.ShibAuthentication;
import org.dspace.authenticate.factory.AuthenticateServiceFactory;
import org.dspace.authorize.AuthorizeException;
import org.dspace.content.clarin.ClarinUserRegistration;
import org.dspace.core.Context;
import org.dspace.eperson.EPerson;
import org.dspace.eperson.Group;
import org.dspace.eperson.service.EPersonService;

/**
 * Authenticate trusted SP identities, provisioning new accounts without email-based linking.
 * Existing profiles, credentials, registrations and explicit groups are preserved.
 * canLogIn retains its legacy native-password meaning for institutional accounts.
 */
public class ClarinShibAuthentication extends ShibAuthentication {
    public static final String ACCOUNT_REVIEW_REQUIRED = "shib.account-review-required";
    public static final String INVALID_ATTRIBUTES = "shib.invalid-attributes";
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
        request.removeAttribute(INVALID_ATTRIBUTES);
        // The old email-verification protocol is not a substitute for a fresh SP session.
        if (request.getHeader("verification-token") != null || request.getParameter("verification-token") != null
                || request.getAttribute("shib.headers") != null) {
            return BAD_ARGS;
        }
        ShibHeaders headers = new ShibHeaders(request);
        try {
            List<String> identifiers = qualifiedIdentifiers(headers.getNetIdHeaders(), headers);
            EPerson person = resolve(identifiers, ePersonService, context);
            if (person == null) {
                if (!configurationService.getBooleanProperty("authentication-shibboleth.autoregister", true)) {
                    request.setAttribute(ACCOUNT_REVIEW_REQUIRED, true);
                    return NO_SUCH_USER;
                }
                // A new registration requires a trusted SP session and one usable email.
                single(headers, "Shib-Session-ID", true);
                String email = single(headers, configurationService.getProperty(
                        "authentication-shibboleth.email-header", "mail"), true).toLowerCase(Locale.ROOT);
                if (email.length() > 256 || !validEmail(email)) {
                    throw new IllegalArgumentException("Invalid federation attributes");
                }
                String first = single(headers, configurationService.getProperty(
                        "authentication-shibboleth.firstname-header", "givenName"), false);
                String last = single(headers, configurationService.getProperty(
                        "authentication-shibboleth.lastname-header", "sn"), false);
                UUID id = provision(context, identifiers, email, first, last);
                if (id == null) {
                    request.setAttribute(ACCOUNT_REVIEW_REQUIRED, true);
                    return NO_SUCH_USER;
                }
                person = ePersonService.find(context, id);
                if (person == null) {
                    throw new SQLException("Provisioned institutional account is unavailable");
                }
            }
            context.setCurrentUser(person);
            request.setAttribute("shib.authenticated", true);
            return SUCCESS;
        } catch (IllegalArgumentException e) {
            request.setAttribute(INVALID_ATTRIBUTES, true);
            return NO_SUCH_USER;
        }
    }

    /** Reject ambiguity before lookup so malformed identity data can never become a new account. */
    private static List<String> qualifiedIdentifiers(String[] names, ShibHeaders headers) {
        String issuer = single(headers, "Shib-Identity-Provider", true);
        List<String> identifiers = new ArrayList<>();
        if (names != null) {
            for (String name : names) {
                String value = single(headers, name.trim(), false);
                if (value != null) {
                    // Preserve legacy identifier[issuer] values without allowing delimiter ambiguity.
                    if (value.contains("[") || value.contains("]") || issuer.contains("[") || issuer.contains("]")) {
                        throw new IllegalArgumentException("Invalid federation attributes");
                    }
                    String qualified = Util.formatNetId(value, issuer);
                    if (qualified.length() > 256) {
                        throw new IllegalArgumentException("Invalid federation attributes");
                    }
                    identifiers.add(qualified);
                }
            }
        }
        if (identifiers.isEmpty()) {
            throw new IllegalArgumentException("Missing federation identity");
        }
        return identifiers;
    }

    private static boolean validEmail(String email) {
        try {
            InternetAddress address = new InternetAddress(email, true);
            address.validate();
            return email.equals(address.getAddress());
        } catch (AddressException e) {
            return false;
        }
    }

    private static String single(ShibHeaders headers, String name, boolean required) {
        List<String> values = StringUtils.isBlank(name) ? null : headers.get(name);
        if (values == null && !required) {
            return null;
        }
        if (values == null || values.size() != 1 || StringUtils.isBlank(values.get(0))
                || values.get(0).chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("Invalid federation attributes");
        }
        return values.get(0);
    }

    private static EPerson resolve(List<String> identifiers, EPersonService people, Context context)
            throws SQLException {
        EPerson match = null;
        for (String identifier : identifiers) {
            EPerson candidate = people.findByNetid(context, identifier);
            if (candidate != null) {
                if (match != null && !match.getID().equals(candidate.getID())) {
                    throw new IllegalArgumentException("Conflicting federation identities");
                }
                match = candidate;
            }
        }
        return match;
    }

    /** Retained for API callers; authentication distinguishes malformed identities from unknown ones. */
    public static EPerson findEpersonByNetId(String[] names, ShibHeaders headers,
                                            EPersonService people, Context context, boolean logAllowed)
            throws SQLException {
        try {
            return resolve(qualifiedIdentifiers(names, headers), people, context);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * Commit EPerson and CLARIN registration together in the callback transaction. Existing
     * database unique constraints arbitrate races across backend processes. A losing insert
     * is rolled back, then resolved in a fresh transaction; email alone never authenticates.
     */
    protected UUID provision(Context registration, List<String> identifiers, String email, String first, String last)
            throws SQLException {
        for (int attempt = 0; attempt < 2; attempt++) {
            try {
                EPerson existing = resolve(identifiers, ePersonService, registration);
                if (existing != null) {
                    return existing.getID();
                }
                if (ePersonService.findByEmail(registration, email) != null) {
                    return null;
                }
                registration.turnOffAuthorisationSystem();
                try {
                    EPerson person = ePersonService.create(registration);
                    person.setNetid(identifiers.get(0));
                    person.setEmail(email);
                    person.setCanLogIn(false); // Native password login is not provisioned.
                    person.setSelfRegistered(true);
                    if (first != null) {
                        person.setFirstName(registration, StringUtils.left(first, NAME_MAX_SIZE));
                    }
                    if (last != null) {
                        person.setLastName(registration, StringUtils.left(last, NAME_MAX_SIZE));
                    }
                    ePersonService.update(registration, person);
                    ClarinUserRegistration record = new ClarinUserRegistration();
                    record.setPersonID(person.getID());
                    record.setEmail(email);
                    record.setOrganization(identifiers.get(0));
                    record.setConfirmation(true);
                    clarinUserRegistrationService.create(registration, record);
                    UUID id = person.getID();
                    // Flush here: event consumers may otherwise catch a constraint error
                    // and leave commit() returning after a rollback-only transaction.
                    registration.flush();
                    registration.commit();
                    return id;
                } finally {
                    registration.restoreAuthSystemState();
                }
            } catch (AuthorizeException e) {
                registration.rollback();
                throw new SQLException("Unable to provision institutional account");
            } catch (SQLException | RuntimeException e) {
                registration.rollback();
                if (attempt == 0 && isUniqueConflict(e)) {
                    continue;
                }
                // Do not expose SQL parameters or IdP attributes through authentication logs.
                throw new SQLException("Unable to provision institutional account");
            }
        }
        throw new SQLException("Unable to provision institutional account");
    }

    private static boolean isUniqueConflict(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof SQLException && "23505".equals(((SQLException) cause).getSQLState())) {
                return true;
            }
        }
        return false;
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
