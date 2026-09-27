/**
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE and NOTICE files at the root of the source
 * tree and available online at
 *
 * http://www.dspace.org/license/
 */
package org.dspace.authenticate.clarin;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.dspace.AbstractDSpaceTest;
import org.dspace.authenticate.AuthenticationMethod;
import org.dspace.core.Context;
import org.dspace.eperson.EPerson;
import org.dspace.eperson.service.EPersonService;
import org.dspace.services.factory.DSpaceServicesFactory;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

public class ClarinExistingAccountTest extends AbstractDSpaceTest {
    private static class TestProvider extends ClarinShibAuthentication {
        private int provisioningCalls;
        private UUID created;
        @Override
        protected UUID provision(Context context, List<String> identifiers, String email, String first, String last) {
            provisioningCalls++;
            return created;
        }
        TestProvider(EPersonService people) {
            this.ePersonService = people;
        }
    }

    private EPersonService people;
    private TestProvider provider;
    private EPerson alice;
    private EPerson bob;

    @Before
    public void preparePolicy() throws Exception {
        DSpaceServicesFactory.getInstance().getConfigurationService()
                .setProperty("authentication-shibboleth.netid-header", "eppn,persistent-id");
        DSpaceServicesFactory.getInstance().getConfigurationService()
                .setProperty("authentication-shibboleth.autoregister", false);
        DSpaceServicesFactory.getInstance().getConfigurationService()
                .setProperty("authentication-shibboleth.email-header", "mail");
        people = mock(EPersonService.class);
        provider = new TestProvider(people);
        alice = mock(EPerson.class);
        bob = mock(EPerson.class);
    }

    private MockHttpServletRequest request(String id) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Shib-Identity-Provider", "https://idp.auth.test/idp");
        request.addHeader("eppn", id);
        request.addHeader("mail", "same@auth.test");
        request.addHeader("Shib-Session-ID", "session");
        return request;
    }

    @Test
    public void exactMatchPreservesAccountWithoutWriting() throws Exception {
        Context context = mock(Context.class);
        when(people.findByNetid(context, "alice[https://idp.auth.test/idp]")).thenReturn(alice);
        assertEquals(AuthenticationMethod.SUCCESS, provider.authenticate(context, null, null, null, request("alice")));
        verify(context).setCurrentUser(alice);
        verify(people, never()).findByEmail(any(), anyString());
        verify(people, never()).create(any());
        verify(people, never()).update(any(), any());
    }

    @Test
    public void registrationDisabledCannotLinkOrCreate() throws Exception {
        Context context = mock(Context.class);
        MockHttpServletRequest request = request("unmatched");
        assertEquals(AuthenticationMethod.NO_SUCH_USER, provider.authenticate(context, null, null, null, request));
        assertEquals(true, request.getAttribute(ClarinShibAuthentication.ACCOUNT_REVIEW_REQUIRED));
        verify(people, never()).findByEmail(any(), anyString());
        verify(people, never()).create(any());
        verify(people, never()).update(any(), any());
        verify(context, never()).setCurrentUser(any());
    }

    @Test
    public void conflictingAndMultivaluedIdentifiersFailClosed() throws Exception {
        when(alice.getID()).thenReturn(UUID.randomUUID());
        when(bob.getID()).thenReturn(UUID.randomUUID());
        Context context = mock(Context.class);
        when(people.findByNetid(context, "alice[https://idp.auth.test/idp]")).thenReturn(alice);
        when(people.findByNetid(context, "bob[https://idp.auth.test/idp]")).thenReturn(bob);
        MockHttpServletRequest request = request("alice");
        request.addHeader("persistent-id", "bob");
        assertEquals(AuthenticationMethod.NO_SUCH_USER, provider.authenticate(context, null, null, null, request));
        request = request("alice");
        request.addHeader("eppn", "bob");
        assertEquals(AuthenticationMethod.NO_SUCH_USER, provider.authenticate(context, null, null, null, request));
    }

    @Test
    public void missingIssuerAndVerificationTokenCannotAuthenticate() throws Exception {
        Context context = mock(Context.class);
        MockHttpServletRequest request = request("alice");
        request.removeHeader("Shib-Identity-Provider");
        assertEquals(AuthenticationMethod.NO_SUCH_USER, provider.authenticate(context, null, null, null, request));
        request = request("alice");
        request.addHeader("Verification-Token", "synthetic-only");
        assertEquals(AuthenticationMethod.BAD_ARGS, provider.authenticate(context, null, null, null, request));
        assertNull(request.getAttribute("shib.authenticated"));
    }

    @Test
    public void newIdentityProvisionsOnlyAfterAttributeValidation() throws Exception {
        DSpaceServicesFactory.getInstance().getConfigurationService()
                .setProperty("authentication-shibboleth.autoregister", true);
        Context context = mock(Context.class);
        provider.created = UUID.randomUUID();
        when(people.find(context, provider.created)).thenReturn(alice);
        assertEquals(AuthenticationMethod.SUCCESS, provider.authenticate(context, null, null, null, request("new")));
        assertEquals(1, provider.provisioningCalls);
        verify(context).setCurrentUser(alice);
    }

    @Test
    public void malformedAttributesNeverProvision() throws Exception {
        DSpaceServicesFactory.getInstance().getConfigurationService()
                .setProperty("authentication-shibboleth.autoregister", true);
        for (String header : new String[] {"Shib-Identity-Provider", "Shib-Session-ID"}) {
            MockHttpServletRequest missing = request("new");
            missing.removeHeader(header);
            assertEquals(AuthenticationMethod.NO_SUCH_USER,
                    provider.authenticate(mock(Context.class), null, null, null, missing));
            assertEquals(true, missing.getAttribute(ClarinShibAuthentication.INVALID_ATTRIBUTES));
        }
        for (String header : new String[] {"Shib-Identity-Provider", "eppn", "Shib-Session-ID", "mail"}) {
            MockHttpServletRequest ambiguous = request("new");
            ambiguous.addHeader(header, "another-value");
            assertEquals(AuthenticationMethod.NO_SUCH_USER,
                    provider.authenticate(mock(Context.class), null, null, null, ambiguous));
        }
        assertEquals(0, provider.provisioningCalls);
    }

    @Test
    public void emailFallbackIsIssuerBoundAndNeverLooksUpByEmail() throws Exception {
        Context context = mock(Context.class);
        String key = ClarinShibAuthentication.emailIdentity("https://idp.auth.test/idp", "same@auth.test");
        assertEquals(key, ClarinShibAuthentication.emailIdentity("https://idp.auth.test/idp", "SAME@auth.test"));
        org.junit.Assert.assertNotEquals(key,
                ClarinShibAuthentication.emailIdentity("https://other.auth.test/idp", "same@auth.test"));
        org.junit.Assert.assertFalse(key.contains("["));
        when(people.findByNetid(context, key)).thenReturn(alice);
        MockHttpServletRequest request = request("ignored");
        request.removeHeader("eppn");
        assertEquals(AuthenticationMethod.SUCCESS, provider.authenticate(context, null, null, null, request));
        verify(context).setCurrentUser(alice);
        verify(people, never()).findByEmail(any(), anyString());
        request.removeHeader("mail");
        assertEquals(AuthenticationMethod.NO_SUCH_USER, provider.authenticate(context, null, null, null, request));
        assertEquals(true, request.getAttribute(ClarinShibAuthentication.INVALID_ATTRIBUTES));
    }

    @Test
    public void newEmailOnlyAndNetidOnlyIdentitiesCanProvision() throws Exception {
        DSpaceServicesFactory.getInstance().getConfigurationService()
                .setProperty("authentication-shibboleth.autoregister", true);
        provider.created = UUID.randomUUID();
        for (String absent : new String[] {"eppn", "mail"}) {
            Context context = mock(Context.class);
            when(people.find(context, provider.created)).thenReturn(alice);
            MockHttpServletRequest request = request("new");
            request.removeHeader(absent);
            assertEquals(AuthenticationMethod.SUCCESS, provider.authenticate(context, null, null, null, request));
            verify(context).setCurrentUser(alice);
        }
        assertEquals(2, provider.provisioningCalls);
    }

    @Test
    public void concurrentRequestsCannotExchangeIdentityOrFailureState() throws Exception {
        CyclicBarrier barrier = new CyclicBarrier(2);
        when(people.findByNetid(any(), anyString())).thenAnswer(invocation -> {
            barrier.await(5, TimeUnit.SECONDS);
            return invocation.<String>getArgument(1).startsWith("alice[") ? alice : null;
        });
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            for (int i = 0; i < 30; i++) {
                Context accepted = mock(Context.class);
                Context denied = mock(Context.class);
                Future<Integer> a = pool.submit(
                        () -> provider.authenticate(accepted, null, null, null, request("alice")));
                Future<Integer> b = pool.submit(
                        () -> provider.authenticate(denied, null, null, null, request("unknown")));
                assertEquals(Integer.valueOf(AuthenticationMethod.SUCCESS), a.get(10, TimeUnit.SECONDS));
                assertEquals(Integer.valueOf(AuthenticationMethod.NO_SUCH_USER), b.get(10, TimeUnit.SECONDS));
                verify(accepted).setCurrentUser(alice);
                verify(denied, never()).setCurrentUser(any());
            }
        } finally {
            pool.shutdownNow();
        }
    }
}
