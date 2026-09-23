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
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.dspace.app.rest.security.DSpaceAuthentication;
import org.dspace.app.rest.security.RestAuthenticationService;
import org.dspace.app.rest.security.StatelessLoginFilter;
import org.dspace.authenticate.clarin.ClarinShibAuthentication;
import org.dspace.core.Context;
import org.dspace.services.ConfigurationService;
import org.dspace.services.factory.DSpaceServicesFactory;
import org.dspace.web.ContextUtil;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/** SP-protected callback. All request state stays on the request, never on this shared filter. */
public class ClarinShibbolethLoginFilter extends StatelessLoginFilter {
    public static final String USER_WITHOUT_EMAIL_EXCEPTION = "UserWithoutEmailException";
    public static final String MISSING_HEADERS_FROM_IDP = "MissingHeadersFromIpd";
    public static final String VERIFICATION_TOKEN_HEADER = "Verification-Token";
    private static final String INVALID_RETURN = "shib.invalid-return";
    private final ConfigurationService configurationService = DSpaceServicesFactory.getInstance()
            .getConfigurationService();

    public ClarinShibbolethLoginFilter(String url, AuthenticationManager authenticationManager,
                                     RestAuthenticationService restAuthenticationService) {
        super(url, authenticationManager, restAuthenticationService);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res) {
        if (!ClarinShibAuthentication.isEnabled()) {
            throw new ProviderNotFoundException("Shibboleth is disabled.");
        }
        if (!isSafeReturn(req.getParameter("redirectUrl"), configurationService.getProperty("dspace.ui.url"))) {
            req.setAttribute(INVALID_RETURN, true);
            throw new BadCredentialsException("Invalid login return destination.");
        }
        if (req.getHeader(VERIFICATION_TOKEN_HEADER) != null || req.getParameter(VERIFICATION_TOKEN_HEADER) != null
                || req.getParameter("verification-token") != null) {
            throw new BadCredentialsException("Account review is required.");
        }
        // A prior REST cookie must not turn the SP callback into a token refresh for another user.
        Context context = ContextUtil.obtainContext(req);
        context.setCurrentUser(null);
        context.setAuthenticationMethod(null);
        if (!context.getSpecialGroupUuids().isEmpty()) {
            context.getSpecialGroupUuids().clear();
        }
        req.removeAttribute("shib.authenticated");
        Authentication result = authenticationManager.authenticate(new DSpaceAuthentication());
        if (!Boolean.TRUE.equals(req.getAttribute("shib.authenticated"))) {
            context.setCurrentUser(null);
            throw new BadCredentialsException("An institutional identity match is required.");
        }
        context.setAuthenticationMethod("shibboleth");
        return result;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest req, HttpServletResponse res,
                                            FilterChain chain, Authentication auth)
            throws IOException, ServletException {
        String target = req.getParameter("redirectUrl");
        String ui = configurationService.getProperty("dspace.ui.url");
        // Defense in depth: validate before issuing any cookie, even if this method is called directly.
        if (!isSafeReturn(target, ui)) {
            res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid login return destination.");
            return;
        }
        restAuthenticationService.addAuthenticationDataForUser(req, res, (DSpaceAuthentication) auth, true);
        res.sendRedirect(StringUtils.isBlank(target) ? ui : target);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest req, HttpServletResponse res,
                                              AuthenticationException failed) throws IOException, ServletException {
        if (Boolean.TRUE.equals(req.getAttribute(INVALID_RETURN))) {
            res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid login return destination.");
            return;
        }
        res.setHeader("WWW-Authenticate", restAuthenticationService.getWwwAuthenticateHeaderValue(req, res));
        // Identical response for unknown identities and email collisions; no personal data in URLs or logs.
        res.sendRedirect(configurationService.getProperty("dspace.ui.url")
                + "/login?error=shibboleth-account-review-required");
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
