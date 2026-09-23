/**
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE and NOTICE files at the root of the source
 * tree and available online at
 *
 * http://www.dspace.org/license/
 */
package org.dspace.authenticate.clarin;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.layout.PatternLayout;
import org.dspace.AbstractDSpaceTest;
import org.dspace.core.Context;
import org.dspace.eperson.Group;
import org.dspace.eperson.service.GroupService;
import org.dspace.services.ConfigurationService;
import org.dspace.services.factory.DSpaceServicesFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

public class ShibGroupLoggingTest extends AbstractDSpaceTest {
    private static final String EMAIL = "private-email-marker@auth.test";
    private static final String ENTITLEMENT = "private-entitlement-marker";
    private final List<String> messages = new ArrayList<>();
    private Logger logger;
    private Level previousLevel;
    private boolean previousAdditive;
    private AbstractAppender appender;
    private ShibGroup mapping;

    @Before
    public void captureDebugOutput() {
        ConfigurationService config = DSpaceServicesFactory.getInstance().getConfigurationService();
        config.setProperty("authentication-shibboleth.role-header", "entitlement");
        config.setProperty("authentication-shibboleth.email-header", "mail");
        config.setProperty("authentication-shibboleth.role-header.ignore-scope", false);
        config.setProperty("authentication-shibboleth.role-header.ignore-value", false);
        config.setProperty("authentication-shibboleth.role." + ENTITLEMENT, "Synthetic mapped group");
        config.setProperty("authentication-shibboleth.default.auth.group", "");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Shib-Identity-Provider", "https://idp.auth.test/idp");
        request.addHeader("mail", EMAIL);
        request.addHeader("entitlement", ENTITLEMENT);
        mapping = new ShibGroup(new ShibHeaders(request), mock(Context.class));
        mapping.groupService = mock(GroupService.class);

        logger = (Logger) LogManager.getLogger(ShibGroup.class);
        previousLevel = logger.getLevel();
        previousAdditive = logger.isAdditive();
        appender = new AbstractAppender("shib-group-capture", null, PatternLayout.createDefaultLayout(), false) {
            @Override
            public void append(LogEvent event) {
                messages.add(event.getLevel() + " " + event.getMessage().getFormattedMessage());
                if (event.getThrown() != null) {
                    messages.add(event.getThrown().toString());
                }
            }
        };
        appender.start();
        logger.addAppender(appender);
        logger.setAdditive(false);
        logger.setLevel(Level.DEBUG);
    }

    @After
    public void restoreLogger() {
        logger.removeAppender(appender);
        logger.setLevel(previousLevel);
        logger.setAdditive(previousAdditive);
        appender.stop();
    }

    @Test
    public void debugLoggingPreservesMappingWithoutAttributeValues() throws Exception {
        Group group = mock(Group.class);
        UUID id = UUID.randomUUID();
        when(group.getID()).thenReturn(id);
        when(mapping.groupService.findByName(any(), anyString())).thenReturn(group);
        assertEquals(List.of(id), mapping.get());
        assertTrue(messages.stream().anyMatch(message -> message.startsWith("DEBUG ")));
        assertRedacted();
    }

    @Test
    public void failedLookupDoesNotExposeExceptionAttributeValues() throws Exception {
        when(mapping.groupService.findByName(any(), anyString()))
                .thenThrow(new SQLException(EMAIL + " " + ENTITLEMENT));
        assertTrue(mapping.get().isEmpty());
        assertTrue(messages.stream().anyMatch(message -> message.startsWith("ERROR ")));
        assertRedacted();
    }

    private void assertRedacted() {
        String output = String.join("\n", messages);
        assertFalse(output.contains(EMAIL));
        assertFalse(output.contains(ENTITLEMENT));
    }
}
