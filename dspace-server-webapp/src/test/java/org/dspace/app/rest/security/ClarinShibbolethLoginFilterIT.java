/**
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE and NOTICE files at the root of the source
 * tree and available online at
 *
 * http://www.dspace.org/license/
 */
package org.dspace.app.rest.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.Cookie;

import com.nimbusds.jwt.JWTParser;
import org.dspace.app.rest.test.AbstractControllerIntegrationTest;
import org.dspace.app.util.Util;
import org.dspace.builder.BitstreamBuilder;
import org.dspace.builder.CollectionBuilder;
import org.dspace.builder.CommunityBuilder;
import org.dspace.builder.EPersonBuilder;
import org.dspace.builder.GroupBuilder;
import org.dspace.builder.ItemBuilder;
import org.dspace.content.Bitstream;
import org.dspace.content.Collection;
import org.dspace.content.Item;
import org.dspace.eperson.EPerson;
import org.dspace.eperson.Group;
import org.dspace.eperson.factory.EPersonServiceFactory;
import org.dspace.services.ConfigurationService;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/** Real DSpace/H2 account and permission tests, with the SP boundary tested separately by the Docker lab. */
public class ClarinShibbolethLoginFilterIT extends AbstractControllerIntegrationTest {
    private static final String IDP = "https://idp.auth.test/idp";
    private static final String CALLBACK = "/api/authn/shibboleth";
    private EPerson institutional;
    private Group preservedGroup;

    @Autowired
    private ConfigurationService configurationService;

    @Before
    public void configure() throws Exception {
        configurationService.setProperty("plugin.sequence.org.dspace.authenticate.AuthenticationMethod",
            new String[] {"org.dspace.authenticate.clarin.ClarinShibAuthentication",
                "org.dspace.authenticate.PasswordAuthentication"});
        configurationService.setProperty("authentication-shibboleth.netid-header", "eppn,persistent-id");
        configurationService.setProperty("authentication-shibboleth.autoregister", true);
        configurationService.setProperty("authentication-shibboleth.lazysession.loginurl",
                "https://repository.auth.test/Shibboleth.sso/Login");
        configurationService.setProperty("dspace.ui.url", "https://repository.auth.test/repository");
        context.turnOffAuthorisationSystem();
        institutional = EPersonBuilder.createEPerson(context).withEmail("institutional@auth.test")
                .withNameInMetadata("Existing", "Account").withCanLogin(false)
                .withNetId(Util.formatNetId("known", IDP)).build();
        preservedGroup = GroupBuilder.createGroup(context).withName("Preserved institutional permission")
                .addMember(institutional).build();
        context.restoreAuthSystemState();
    }

    private MockHttpServletRequestBuilder login(String identifier, String email) {
        return get(CALLBACK).header("Shib-Identity-Provider", IDP).header("Shib-Session-ID", "synthetic-session")
                .header("eppn", identifier).header("mail", email);
    }

    @Test
    public void exactIdentityKeepsUuidProfileGroupsAndCount() throws Exception {
        int count = EPersonServiceFactory.getInstance().getEPersonService().countTotal(context);
        for (int i = 0; i < 2; i++) {
            MockHttpServletResponse response = getClient().perform(login("known", "changed@auth.test")
                    .param("redirectUrl", "https://repository.auth.test/repository/items/one?x=1&y=2"))
                    .andExpect(status().isFound()).andExpect(redirectedUrl(
                            "https://repository.auth.test/repository/items/one?x=1&y=2"))
                    .andReturn().getResponse();
            Cookie cookie = response.getCookie(AUTHORIZATION_COOKIE);
            assertNotNull(cookie);
            String token = cookie.getValue().replace("Bearer ", "");
            assertEquals(institutional.getID().toString(),
                    JWTParser.parse(token).getJWTClaimsSet().getStringClaim("eid"));
            assertEquals("shibboleth",
                    JWTParser.parse(token).getJWTClaimsSet().getStringClaim("authenticationMethod"));
        }
        context.uncacheEntity(institutional);
        EPerson actual = EPersonServiceFactory.getInstance().getEPersonService().find(context, institutional.getID());
        assertEquals("institutional@auth.test", actual.getEmail());
        assertEquals(Util.formatNetId("known", IDP), actual.getNetid());
        assertTrue(EPersonServiceFactory.getInstance().getGroupService().isMember(context, actual, preservedGroup));
        assertEquals(count, EPersonServiceFactory.getInstance().getEPersonService().countTotal(context));
    }

    @Test
    public void emailOnlyAndUnknownMatchesCannotCreateOrLink() throws Exception {
        int count = EPersonServiceFactory.getInstance().getEPersonService().countTotal(context);
        for (String email : new String[] {eperson.getEmail(), institutional.getEmail(), "new@auth.test"}) {
            MockHttpServletResponse response = getClient().perform(login("unmatched", email))
                    .andExpect(status().isFound()).andExpect(redirectedUrl(
                            "https://repository.auth.test/repository/login?error=shibboleth-account-review-required"))
                    .andReturn().getResponse();
            assertNull(response.getCookie(AUTHORIZATION_COOKIE));
        }
        assertEquals(count, EPersonServiceFactory.getInstance().getEPersonService().countTotal(context));
        assertNull(eperson.getNetid());
        assertEquals(Util.formatNetId("known", IDP), institutional.getNetid());
    }

    @Test
    public void existingIdentityDoesNotNeedEmailVerification() throws Exception {
        MockHttpServletResponse response = getClient().perform(get(CALLBACK)
                .header("Shib-Identity-Provider", IDP).header("eppn", "known"))
                .andExpect(status().isFound()).andReturn().getResponse();
        assertNotNull(response.getCookie(AUTHORIZATION_COOKIE));
    }

    @Test
    public void maliciousReturnCannotIssueCookie() throws Exception {
        MockHttpServletResponse response = getClient().perform(login("known", "institutional@auth.test")
                .param("redirectUrl", "http://repository.auth.test/repository/"))
                .andExpect(status().isBadRequest()).andReturn().getResponse();
        assertNull(response.getCookie(AUTHORIZATION_COOKIE));
    }

    @Test
    public void passwordRecoveryRemainsIndependent() throws Exception {
        assertNotNull(getAuthToken(eperson.getEmail(), password));
    }

    @Test
    public void priorPasswordSessionCannotBypassInstitutionalMatching() throws Exception {
        String localToken = getAuthToken(eperson.getEmail(), password);
        MockHttpServletResponse denied = getClient(localToken).perform(login("unmatched", eperson.getEmail()))
                .andExpect(status().isFound()).andExpect(redirectedUrl(
                        "https://repository.auth.test/repository/login?error=shibboleth-account-review-required"))
                .andReturn().getResponse();
        assertNull(denied.getCookie(AUTHORIZATION_COOKIE));
        MockHttpServletResponse accepted = getClient(localToken).perform(login("known", "institutional@auth.test"))
                .andExpect(status().isFound()).andReturn().getResponse();
        String value = accepted.getCookie(AUTHORIZATION_COOKIE).getValue().replace("Bearer ", "");
        assertEquals(institutional.getID().toString(), JWTParser.parse(value).getJWTClaimsSet().getStringClaim("eid"));
    }

    @Test
    public void institutionalLoginPreservesRestrictedDownloadRights() throws Exception {
        context.turnOffAuthorisationSystem();
        parentCommunity = CommunityBuilder.createCommunity(context).withName("Auth fixture").build();
        Collection collection = CollectionBuilder.createCollection(context, parentCommunity).withName("Files").build();
        Item item = ItemBuilder.createItem(context, collection).withTitle("Synthetic restricted item").build();
        Bitstream restricted = BitstreamBuilder.createBitstream(context, item,
                new ByteArrayInputStream("synthetic content".getBytes(StandardCharsets.UTF_8)))
                .withName("restricted.txt").withMimeType("text/plain").withReaderGroup(preservedGroup).build();
        context.restoreAuthSystemState();
        String path = "/api/core/bitstreams/" + restricted.getID() + "/content";
        getClient().perform(get(path)).andExpect(status().isUnauthorized());
        String unrelated = getAuthToken(eperson.getEmail(), password);
        getClient(unrelated).perform(get(path)).andExpect(status().isForbidden());
        getClient(unrelated).perform(get(path).header("Range", "bytes=0-3")).andExpect(status().isForbidden());
        MockHttpServletResponse response = getClient().perform(login("known", "institutional@auth.test"))
                .andExpect(status().isFound()).andReturn().getResponse();
        String token = response.getCookie(AUTHORIZATION_COOKIE).getValue().replace("Bearer ", "");
        getClient(token).perform(get(path)).andExpect(status().isOk());
        getClient(token).perform(get(path).header("Range", "bytes=0-3")).andExpect(status().isPartialContent());
    }
}
