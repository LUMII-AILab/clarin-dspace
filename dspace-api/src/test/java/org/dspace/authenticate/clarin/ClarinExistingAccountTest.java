/**
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE and NOTICE files at the root of the source
 * tree and available online at
 *
 * http://www.dspace.org/license/
 */
package org.dspace.authenticate.clarin;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.dspace.AbstractDSpaceTest;
import org.dspace.authenticate.AuthenticationMethod;
import org.dspace.content.clarin.ClarinVerificationToken;
import org.dspace.content.service.clarin.ClarinVerificationTokenService;
import org.dspace.core.Context;
import org.dspace.eperson.EPerson;
import org.dspace.eperson.service.EPersonService;
import org.dspace.services.ConfigurationService;
import org.dspace.services.factory.DSpaceServicesFactory;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

public class ClarinExistingAccountTest extends AbstractDSpaceTest {
    private static class TestProvider extends ClarinShibAuthentication {
        EPerson created;
        TestProvider(EPersonService people, ClarinVerificationTokenService tokens) {
            ePersonService = people;
            clarinVerificationTokenService = tokens;
        }
        @Override
        protected void initialize(Context context) {
            metadataHeaderMap = Collections.emptyMap();
        }
        @Override
        protected EPerson registerNewEPerson(Context context, javax.servlet.http.HttpServletRequest request,
                                             String[] headers) {
            return created;
        }
        @Override
        protected void updateEPerson(Context context, javax.servlet.http.HttpServletRequest request,
                                     EPerson person, String[] headers) {
            request.setAttribute("matched.netid", getFirstNetId(headers, request));
        }
    }
    private EPersonService people;
    private ClarinVerificationTokenService tokens;
    private TestProvider provider;
    private EPerson alice;

    @Before
    public void configure() {
        ConfigurationService config = DSpaceServicesFactory.getInstance().getConfigurationService();
        config.setProperty("authentication-shibboleth.netid-header", "eppn");
        config.setProperty("authentication-shibboleth.email-header", "mail");
        config.setProperty("authentication-shibboleth.autoregister", false);
        config.setProperty("authentication-shibboleth.email-use-tomcat-remote-user", false);
        people = mock(EPersonService.class);
        tokens = mock(ClarinVerificationTokenService.class);
        provider = new TestProvider(people, tokens);
        alice = mock(EPerson.class);
    }
    private MockHttpServletRequest request(String id, String email) {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.addHeader("Shib-Identity-Provider", "https://idp.auth.test/idp");
        if (id != null) {
            req.addHeader("eppn", id);
        }
        if (email != null) {
            req.addHeader("mail", email);
        }
        return req;
    }
    private int authenticate(MockHttpServletRequest req, Context context) throws Exception {
        return provider.authenticate(context, null, null, null, req);
    }
    @Test
    public void nativeBindingReusesExistingAccount() throws Exception {
        Context context = mock(Context.class);
        when(people.findByNetid(context, "alice[https://idp.auth.test/idp]")).thenReturn(alice);
        assertEquals(AuthenticationMethod.SUCCESS, authenticate(request("alice", "alice@auth.test"), context));
        verify(context).setCurrentUser(alice);
    }
    @Test
    public void migratedEmailOnlyAccountReusesExistingAccount() throws Exception {
        Context context = mock(Context.class);
        when(people.findByEmail(context, "alice@auth.test")).thenReturn(alice);
        assertEquals(AuthenticationMethod.SUCCESS, authenticate(request("alice", "alice@auth.test"), context));
        verify(context).setCurrentUser(alice);
    }
    @Test
    public void conflictingBindingIsRefused() throws Exception {
        Context context = mock(Context.class);
        when(alice.getNetid()).thenReturn("different[https://idp.auth.test/idp]");
        when(people.findByEmail(context, "alice@auth.test")).thenReturn(alice);
        assertEquals(AuthenticationMethod.NO_SUCH_USER, authenticate(request("alice", "alice@auth.test"), context));
    }
    @Test
    public void duplicateFailureDoesNotPoisonNextRegistration() throws Exception {
        conflictingBindingIsRefused();
        DSpaceServicesFactory.getInstance().getConfigurationService()
                .setProperty("authentication-shibboleth.autoregister", true);
        provider.created = mock(EPerson.class);
        assertEquals(AuthenticationMethod.SUCCESS,
                authenticate(request("new", "new@auth.test"), mock(Context.class)));
    }
    @Test
    public void verificationEmailDoesNotLeakIntoNextRequest() throws Exception {
        ClarinVerificationToken token = new ClarinVerificationToken();
        token.setEmail("alice@auth.test");
        when(tokens.findByToken(any(), anyString())).thenReturn(token);
        when(people.findByEmail(any(), org.mockito.ArgumentMatchers.eq("alice@auth.test"))).thenReturn(alice);
        MockHttpServletRequest verified = request("alice", null);
        verified.addHeader("verification-token", "synthetic-only");
        assertEquals(AuthenticationMethod.SUCCESS, authenticate(verified, mock(Context.class)));
        assertEquals(AuthenticationMethod.NO_SUCH_USER,
                authenticate(request("stranger", null), mock(Context.class)));
    }
    @Test
    public void concurrentRequestsKeepTheirOwnProfileIdentity() throws Exception {
        CountDownLatch aliceEntered = new CountDownLatch(1);
        CountDownLatch bobEntered = new CountDownLatch(1);
        when(people.findByNetid(any(), anyString())).thenAnswer(call -> {
            if (call.<String>getArgument(1).startsWith("alice[")) {
                aliceEntered.countDown();
                if (!bobEntered.await(10, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("Second request did not run");
                }
            } else {
                bobEntered.countDown();
            }
            return alice;
        });
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            MockHttpServletRequest a = request("alice", "alice@auth.test");
            Future<Integer> first = pool.submit(() -> authenticate(a, mock(Context.class)));
            org.junit.Assert.assertTrue(aliceEntered.await(10, TimeUnit.SECONDS));
            Future<Integer> second = pool.submit(
                    () -> authenticate(request("bob", "bob@auth.test"), mock(Context.class)));
            assertEquals(Integer.valueOf(AuthenticationMethod.SUCCESS), first.get(15, TimeUnit.SECONDS));
            assertEquals(Integer.valueOf(AuthenticationMethod.SUCCESS), second.get(15, TimeUnit.SECONDS));
            assertEquals("alice[https://idp.auth.test/idp]", a.getAttribute("matched.netid"));
        } finally {
            pool.shutdownNow();
        }
    }
    @Test
    public void providerLogsDoNotContainIdentityValues() throws Exception {
        org.apache.logging.log4j.core.Logger logger = (org.apache.logging.log4j.core.Logger)
                org.apache.logging.log4j.LogManager.getLogger(ClarinShibAuthentication.class);
        java.util.List<String> messages = new java.util.ArrayList<>();
        org.apache.logging.log4j.Level previous = logger.getLevel();
        org.apache.logging.log4j.core.appender.AbstractAppender capture =
                new org.apache.logging.log4j.core.appender.AbstractAppender("provider-capture", null,
                        org.apache.logging.log4j.core.layout.PatternLayout.createDefaultLayout(), false) {
                    @Override
                    public void append(org.apache.logging.log4j.core.LogEvent event) {
                        messages.add(event.getMessage().getFormattedMessage());
                    }
                };
        capture.start();
        logger.addAppender(capture);
        logger.setLevel(org.apache.logging.log4j.Level.DEBUG);
        try {
            migratedEmailOnlyAccountReusesExistingAccount();
            String output = String.join("\n", messages);
            org.junit.Assert.assertFalse(output.contains("alice@auth.test"));
            org.junit.Assert.assertFalse(output.contains("alice["));
        } finally {
            logger.removeAppender(capture);
            logger.setLevel(previous);
            capture.stop();
        }
    }

    @Test
    public void savedAttributesExcludeBrowserCredentials() {
        MockHttpServletRequest request = request("alice", null);
        for (String header : new String[] {"Cookie", "Authorization", "Verification-Token", "X-XSRF-TOKEN"}) {
            request.addHeader(header, "private-browser-credential");
        }
        String saved = new ShibHeaders(request).toString();
        org.junit.Assert.assertFalse(saved.contains("private-browser-credential"));
        org.junit.Assert.assertTrue(saved.contains("alice"));
    }

}
