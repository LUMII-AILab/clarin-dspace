/**
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE and NOTICE files at the root of the source
 * tree and available online at
 *
 * http://www.dspace.org/license/
 */
package org.dspace.app.rest.security.clarin;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Objects;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.dspace.app.rest.security.DSpaceAuthentication;
import org.dspace.app.rest.security.RestAuthenticationService;
import org.dspace.app.rest.security.StatelessLoginFilter;
import org.dspace.authenticate.clarin.ClarinShibAuthentication;
import org.dspace.authenticate.clarin.ShibHeaders;
import org.dspace.content.clarin.ClarinVerificationToken;
import org.dspace.content.factory.ClarinServiceFactory;
import org.dspace.content.service.clarin.ClarinVerificationTokenService;
import org.dspace.core.Context;
import org.dspace.core.Utils;
import org.dspace.eperson.EPerson;
import org.dspace.eperson.factory.EPersonServiceFactory;
import org.dspace.eperson.service.EPersonService;
import org.dspace.services.ConfigurationService;
import org.dspace.services.factory.DSpaceServicesFactory;
import org.dspace.web.ContextUtil;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * This class is copied from `ShibbolethLoginFilter` and modified by the
 * @author Milan Majchrak (milan.majchrak at dataquest.sk).
 *
 * This class will filter Shibboleth requests to see if the user has been authenticated via Shibboleth.
 * <P>
 * The overall Shibboleth login process is as follows:
 *   1. When Shibboleth plugin is enabled, client/UI receives Shibboleth's absolute URL in WWW-Authenticate header.
 *      See {@link ClarinShibAuthentication} loginPageURL() method.
 *   2. Client sends the user to that URL when they select Shibboleth authentication.
 *   3. User logs in using Shibboleth
 *   4. If successful, they are redirected by Shibboleth to the path where this Filter is "listening" (that path
 *      is passed to Shibboleth as a URL param in step 1)
 *   4.1. This filter then intercepts the request in order to check for a valid Shibboleth login (see
 *      ShibAuthentication.authenticate()) and stores that user info in a JWT. It also saves that JWT in a *temporary*
 *      authentication cookie.
 *   4.2. At that point, the client reads the JWT from the Cookie, and sends it back in a request to /api/authn/login,
 *      which triggers the server-side to destroy the Cookie and move the JWT into a Header
 *   5. If not successful:
 *   5.1. The IdP hasn't sent the `Shib-Identity-Provider` or `SHIB-NETID` header. The user is redirected to the
 *      static error page.
 *   5.2. The IdP hasn't sent the `SHIB-EMAIL` header.
 *      The request headers passed by IdP are stored into the `verification_token` table the `shib_headers` column.
 *      The user is redirected to the page when he must fill his email.
 * <P>
 * This Shibboleth Authentication process is tested in ClarinShibbolethLoginFilterIT.
 *
 * @author Giuseppe Digilio (giuseppe dot digilio at 4science dot it)
 * @author Tim Donohue
 * @see ClarinShibAuthentication
 */
public class ClarinShibbolethLoginFilter extends StatelessLoginFilter {
    public static final String USER_WITHOUT_EMAIL_EXCEPTION = "UserWithoutEmailException";
    public static final String MISSING_HEADERS_FROM_IDP = "MissingHeadersFromIpd";
    private static final String AUTHORIZATION_HEADER = "Authorization";

    public static final String VERIFICATION_REQUEST_COOKIE = "DSPACE-SHIB-VERIFICATION";

    public static final String VERIFICATION_TOKEN_HEADER = "Verification-Token";

    private static final Logger log = LogManager.getLogger(org.dspace.app.rest.security.clarin.
            ClarinShibbolethLoginFilter.class);

    private static final String REQUEST_STATE = ClarinShibbolethLoginFilter.class.getName() + ".state";
    private static final String INVALID_RETURN = "shib.invalid-return";

    private static class RequestState {
        private boolean missingHeaders;
        private boolean emailAssociated;
        private String netId;
    }

    private RequestState state(HttpServletRequest request) {
        return (RequestState) request.getAttribute(REQUEST_STATE);
    }

    private ConfigurationService configurationService = DSpaceServicesFactory.getInstance().getConfigurationService();
    private ClarinVerificationTokenService clarinVerificationTokenService = ClarinServiceFactory.getInstance()
            .getClarinVerificationTokenService();
    private EPersonService ePersonService = EPersonServiceFactory.getInstance().getEPersonService();

    public ClarinShibbolethLoginFilter(String url, AuthenticationManager authenticationManager,
                                 RestAuthenticationService restAuthenticationService) {
        super(url, authenticationManager, restAuthenticationService);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest req,
                                                HttpServletResponse res) throws AuthenticationException {
        req.setAttribute(REQUEST_STATE, new RequestState());
        if (!isSafeReturn(req.getParameter("redirectUrl"), configurationService.getProperty("dspace.ui.url"))) {
            req.setAttribute(INVALID_RETURN, true);
            throw new BadCredentialsException("Invalid login return destination.");
        }

        // First, if Shibboleth is not enabled, throw an immediate ProviderNotFoundException
        // This tells Spring Security that authentication failed
        if (!ClarinShibAuthentication.isEnabled()) {
            throw new ProviderNotFoundException("Shibboleth is disabled.");
        }

        // If the Idp doesn't send the email in the request header, send the redirect order to the FE for the user
        // to fill in the email.
        String emailHeader = configurationService.getProperty("authentication-shibboleth.email-header");

        Context context = ContextUtil.obtainContext(req);
        if (Objects.isNull(context)) {
            throw new RuntimeException("Cannot load the context");
        }

        // The callback must authenticate the fresh institutional identity, not refresh a prior JWT.
        context.setCurrentUser(null);
        context.setAuthenticationMethod(null);
        if (!context.getSpecialGroupUuids().isEmpty()) {
            context.getSpecialGroupUuids().clear();
        }
        req.removeAttribute("shib.authenticated");

        // If the verification token is not null the user wants to login.
        String verificationToken = req.getHeader(VERIFICATION_TOKEN_HEADER);
        ClarinVerificationToken clarinVerificationToken;
        try {
            clarinVerificationToken = clarinVerificationTokenService.findByToken(context, verificationToken);
        } catch (SQLException e) {
            throw new BadCredentialsException("Cannot validate the verification credential.");
        }

        if (StringUtils.isNotBlank(verificationToken) && clarinVerificationToken == null) {
            throw new BadCredentialsException("Invalid verification credential.");
        }

        // Load ShibHeader from request or from clarin verification token object.
        ShibHeaders shib_headers;
        if (Objects.nonNull(clarinVerificationToken)) {
            // Set request attribute for authentication method.
            req.setAttribute("shib.headers", clarinVerificationToken.getShibHeaders());
            shib_headers = new ShibHeaders(clarinVerificationToken.getShibHeaders());
        } else {
            shib_headers = new ShibHeaders(req);
        }

        String idp = shib_headers.get_idp();
        // If the clarin verification object is not null load the email from there otherwise from header.
        String email;
        if (Objects.isNull(clarinVerificationToken)) {
            email = shib_headers.get_single(emailHeader);
            if (StringUtils.isNotEmpty(email)) {
                email = ClarinShibAuthentication.sortEmailsAndGetFirst(email);
            }
        } else {
            email = clarinVerificationToken.getEmail();
        }

        EPerson ePerson = null;
        try {
            ePerson = ClarinShibAuthentication.findEpersonByNetId(shib_headers.getNetIdHeaders(), shib_headers,
                    ePersonService, context, false);
        } catch (SQLException e) {
            // It is logged in the ClarinShibAuthentication class.
        }

        boolean foundByNetId = ePerson != null;
        if (Objects.isNull(ePerson) && StringUtils.isNotEmpty(email)) {
            try {
                ePerson = ePersonService.findByEmail(context, email);
            } catch (SQLException e) {
                // It is logged in the ClarinShibAuthentication class.
            }
        }

        try {
            if (StringUtils.isEmpty(idp)) {
                log.error("Cannot load the idp from the request headers.");
                state(req).missingHeaders = true;
            }

            if (!foundByNetId && ePerson != null && ePerson.getNetid() != null
                    && Objects.isNull(clarinVerificationToken)) {
                log.error("The users email is already associated with a different user");
                state(req).emailAssociated = true;
            }

            // The Idp hasn't sent the email - the user will be redirected to the page where he must fill in that
            // missing email
            if (StringUtils.isBlank(email) && (ePerson == null || StringUtils.isBlank(ePerson.getEmail()))) {
                log.error("Cannot load the shib email header from the request headers.");
                this.setMissingUserEmail(req, res);
                throw new BadCredentialsException("Email verification is required.");
            }
        } catch (IOException e) {
            throw new RuntimeException("Cannot redirect the user to the Shibboleth authentication error page" +
                    " because: " + e.getMessage());
        }

        // In the case of Shibboleth, this method does NOT actually authenticate us. The authentication
        // has already happened in Shibboleth. So, this call to "authenticate()" is just triggering
        // ShibAuthentication.authenticate() to check for a valid Shibboleth login, and if found, the current user
        // is considered authenticated via Shibboleth.
        // NOTE: because this authentication is implicit, we pass in an empty DSpaceAuthentication
        Authentication authentication = authenticationManager.authenticate(new DSpaceAuthentication());
        if (!Boolean.TRUE.equals(req.getAttribute("shib.authenticated"))) {
            context.setCurrentUser(null);
            throw new BadCredentialsException("An institutional identity is required.");
        }
        if (clarinVerificationToken != null) {
            try {
                if (!clarinVerificationTokenService.consume(context, clarinVerificationToken)) {
                    context.abort();
                    throw new BadCredentialsException("Verification credential already used or expired.");
                }
                context.commit();
            } catch (SQLException e) {
                context.abort();
                throw new BadCredentialsException("Cannot consume the verification credential.");
            }
        }
        return authentication;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest req,
                                            HttpServletResponse res,
                                            FilterChain chain,
                                            Authentication auth) throws IOException, ServletException {
        if (!isSafeReturn(req.getParameter("redirectUrl"), configurationService.getProperty("dspace.ui.url"))) {
            res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid login return destination.");
            return;
        }
        // Once we've gotten here, we know we have a successful login (i.e. attemptAuthentication() succeeded)

        DSpaceAuthentication dSpaceAuthentication = (DSpaceAuthentication) auth;
        log.debug("Shibboleth authentication successful; issuing temporary authentication data.");
        // OVERRIDE DEFAULT behavior of StatelessLoginFilter to return a temporary authentication cookie containing
        // the Auth Token (JWT). This Cookie is required because we *redirect* the user back to the client/UI after
        // a successful Shibboleth login. Headers cannot be sent via a redirect, so a Cookie must be sent to provide
        // the auth token to the client. On the next request from the client, the cookie is read and destroyed & the
        // Auth token is only used in the Header from that point forward.
        restAuthenticationService.addAuthenticationDataForUser(req, res, dSpaceAuthentication, true);

        String verificationToken = req.getHeader(VERIFICATION_TOKEN_HEADER);
        if (StringUtils.isEmpty(verificationToken)) {
            // redirect user after completing Shibboleth authentication, sending along the temporary auth cookie
            redirectAfterSuccess(req, res);
        } else {
            res.getWriter().write(res.getHeader(AUTHORIZATION_HEADER));
        }
    }

    /**
     * If the above attemptAuthentication() call was unsuccessful, then ensure that the response is a 401 Unauthorized
     * AND it includes a WWW-Authentication header. We use this header in DSpace to return all the enabled
     * authentication options available to the UI (along with the path to the login URL for each option)
     * @param request current request
     * @param response current response
     * @param failed exception that was thrown by attemptAuthentication()
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request,
                                              HttpServletResponse response, AuthenticationException failed)
            throws IOException, ServletException {

        if (Boolean.TRUE.equals(request.getAttribute(INVALID_RETURN))) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid login return destination.");
            return;
        }
        if (StringUtils.isNotBlank(request.getHeader(VERIFICATION_TOKEN_HEADER))) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid verification credential.");
            return;
        }
        String authenticateHeaderValue = restAuthenticationService.getWwwAuthenticateHeaderValue(request, response);

        response.setHeader("WWW-Authenticate", authenticateHeaderValue);

        String redirectUrl = configurationService.getProperty("dspace.ui.url") + "/login/";
        String missingHeadersUrl = "missing-headers";
        String userWithoutEmailUrl = "auth-failed";
        String duplicateUser = "duplicate-user";
        String cannotAuthenticate = "shibboleth-authentication-failed";

        // Compose the redirect URL
        if (state(request).missingHeaders) {
            redirectUrl += missingHeadersUrl;
        } else if (state(request).emailAssociated) {
            redirectUrl += duplicateUser;
        } else if (StringUtils.isNotEmpty(state(request).netId)) {
            // Ensure netId is URL-encoded to prevent `+` from turning into a space
            String encodedNetId = URLEncoder.encode(state(request).netId, StandardCharsets.UTF_8);
            redirectUrl += userWithoutEmailUrl + "?netid=" + encodedNetId;
        } else {
            // Remove the last slash from the URL `login/`
            String redirectUrlWithoutSlash = redirectUrl.endsWith("/") ?
                    Utils.replaceLast(redirectUrl, "/", "") : redirectUrl;
            redirectUrl = redirectUrlWithoutSlash + "?error=" + cannotAuthenticate;
        }

        response.sendRedirect(redirectUrl);
        log.info("Shibboleth authentication failed (status:{}).", HttpServletResponse.SC_UNAUTHORIZED);
    }


    /**
     * After successful login, redirect to the DSpace URL specified by this Shibboleth request (in the "redirectUrl"
     * request parameter). If that 'redirectUrl' is not valid or trusted for this DSpace site, then return a 400 error.
     * @param request
     * @param response
     * @throws IOException
     */
    private void redirectAfterSuccess(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Get redirect URL from request parameter
        String redirectUrl = request.getParameter("redirectUrl");

        // If redirectUrl unspecified, default to the configured UI
        if (StringUtils.isEmpty(redirectUrl)) {
            redirectUrl = configurationService.getProperty("dspace.ui.url");
        }

        response.sendRedirect(org.dspace.app.rest.utils.Utils.encodeNonAsciiCharacters(redirectUrl));
    }

    /**
     * The IdP hasn't sent the `SHIB-EMAIL` header. The user is redirected to the page where he must fill in his
     * email. (The UI process error message).
     * The request headers passed by IdP are stored into the `verification_token` table the `shib_headers` column
     * for later usage. After successful signing in the `verification_token` record is removed from the DB.
     */
    protected void setMissingUserEmail(HttpServletRequest req,
                                            HttpServletResponse res) throws IOException {
        Context context = ContextUtil.obtainContext(req);
        String authenticateHeaderValue = restAuthenticationService.getWwwAuthenticateHeaderValue(req, res);

        // Store the header which the Idp has sent to the ShibHeaders object and save that header into the table
        // `verification_token` because after successful authentication the Idp headers will be showed for the user in
        // the another page.
        // Store header values in the ShibHeaders because of String issues.
        ShibHeaders shib_headers = new ShibHeaders(req);
        String[] netIdHeaders = shib_headers.getNetIdHeaders();
        String netId = getNetIdFromShibHeaders(netIdHeaders, shib_headers);

        if (StringUtils.isBlank(netId) || StringUtils.isBlank(shib_headers.get_idp())) {
            state(req).missingHeaders = true;
            return;
        }

        // Store the Idp headers associated with the current netid.
        ClarinVerificationToken clarinVerificationToken;
        try {
            clarinVerificationToken = clarinVerificationTokenService.findByNetID(context, netId);
            if (Objects.isNull(clarinVerificationToken)) {
                clarinVerificationToken = clarinVerificationTokenService.create(context);
                clarinVerificationToken.setePersonNetID(netId);
            }
            clarinVerificationToken.setShibHeaders(shib_headers.toString());
            clarinVerificationToken.setRequestToken(Utils.generateHexKey());
            clarinVerificationToken.setToken(null);
            clarinVerificationToken.setEmail(null);
            clarinVerificationToken.setExpires(Date.from(Instant.now().plus(Duration.ofHours(24))));
            clarinVerificationTokenService.update(context, clarinVerificationToken);
            context.commit();
        } catch (SQLException e) {
            throw new RuntimeException("Cannot create or update the Clarin Verification Token because: "
                    + e.getMessage());
        }

        String cookiePath = URI.create(configurationService.getProperty("dspace.server.url")).getPath()
                + "/api/autoregistration";
        res.addHeader("Set-Cookie", ResponseCookie.from(VERIFICATION_REQUEST_COOKIE,
                clarinVerificationToken.getRequestToken()).httpOnly(true).secure(req.isSecure())
                .sameSite("Lax").path(cookiePath).maxAge(Duration.ofHours(24)).build().toString());
        state(req).netId = netId;
    }

    private String getEpersonEmail(EPerson ePerson) {
        if (Objects.isNull(ePerson)) {
            return null;
        }
        return ePerson.getEmail();
    }

    /**
     * Get the netId from the ShibHeaders object. The netId is stored in the headers which are defined in the
     * `authentication-shibboleth.netid-headers` property.
     * @return netId or null
     */
    private String getNetIdFromShibHeaders(String[] netIdHeaders, ShibHeaders shibHeaders) {
        for (String netidHeader : netIdHeaders) {
            String netID = shibHeaders.get_single(netidHeader);
            if (StringUtils.isNotEmpty(netID)) {
                return netID;
            }
        }
        return null;
    }
    /** Require the configured UI scheme, host, effective port and path boundary. */
    static boolean isSafeReturn(String value, String uiUrl) {
        try {
            URI ui = new URI(uiUrl);
            URI target = new URI(StringUtils.isBlank(value) ? uiUrl : value);
            String path = target.getRawPath();
            String base = ui.getPath().replaceAll("/+$", "");
            return ui.isAbsolute() && target.isAbsolute() && target.getHost() != null
                    && ui.getScheme().equalsIgnoreCase(target.getScheme())
                    && ui.getHost().equalsIgnoreCase(target.getHost())
                    && effectivePort(ui) == effectivePort(target)
                    && target.getRawUserInfo() == null && path != null
                    && !path.matches("(?i).*%(25|2f|5c|2e).*")
                    && target.normalize().getRawPath().equals(path)
                    && (path.equals(base) || path.startsWith(base + "/"));
        } catch (URISyntaxException | IllegalArgumentException | NullPointerException e) {
            return false;
        }
    }

    private static int effectivePort(URI uri) {
        return uri.getPort() >= 0 ? uri.getPort() : ("https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80);
    }
}
