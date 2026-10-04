/**
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE and NOTICE files at the root of the source
 * tree and available online at
 *
 * http://www.dspace.org/license/
 */
package org.dspace.app.rest.security.clarin;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import org.dspace.AbstractDSpaceTest;
import org.dspace.app.rest.security.DSpaceAuthentication;
import org.dspace.app.rest.security.RestAuthenticationService;
import org.dspace.services.factory.DSpaceServicesFactory;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;

public class ClarinReturnUrlTest extends AbstractDSpaceTest {
    @Test
    public void invalidReturnCannotReceiveAuthenticationData() throws Exception {
        DSpaceServicesFactory.getInstance().getConfigurationService()
                .setProperty("dspace.ui.url", "https://repository.auth.test/repository");
        RestAuthenticationService service = mock(RestAuthenticationService.class);
        ClarinShibbolethLoginFilter filter = new ClarinShibbolethLoginFilter(
                "/api/authn/shibboleth", mock(AuthenticationManager.class), service);
        for (String target : new String[] {"http://repository.auth.test/repository/",
            "https://repository.auth.test:444/repository/", "https://evil.test/"}) {
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.setParameter("redirectUrl", target);
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.successfulAuthentication(request, response, null, new DSpaceAuthentication());
            assertEquals(400, response.getStatus());
            verifyNoInteractions(service);
        }
    }
    private static final String UI = "https://repository.auth.test/repository";

    @Test
    public void preservesNestedSameOriginReturn() {
        assertTrue(ClarinShibbolethLoginFilter.isSafeReturn(UI + "/items/one?x=a%26b&y=2#files", UI));
        assertTrue(ClarinShibbolethLoginFilter.isSafeReturn(null, UI));
        assertTrue(ClarinShibbolethLoginFilter.isSafeReturn("https://repository.auth.test:443/repository/", UI));
    }

    @Test
    public void rejectsUnsafeOriginsAndPathEncodings() {
        String[] bad = {"http://repository.auth.test/repository/", "https://evil.test/repository/",
            "https://repository.auth.test:444/repository/", "//repository.auth.test/repository/",
            "https://user@repository.auth.test/repository/", UI + "-other/", UI + "/../admin",
            UI + "/%2e%2e/admin", UI + "/%252f%252fevil.test", UI + "/%2fadmin", UI + "/%5cadmin"};
        for (String value : bad) {
            assertFalse(value, ClarinShibbolethLoginFilter.isSafeReturn(value, UI));
        }
    }
}
