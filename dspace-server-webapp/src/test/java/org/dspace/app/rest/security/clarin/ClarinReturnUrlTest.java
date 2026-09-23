/**
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE and NOTICE files at the root of the source
 * tree and available online at
 *
 * http://www.dspace.org/license/
 */
package org.dspace.app.rest.security.clarin;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class ClarinReturnUrlTest {
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
