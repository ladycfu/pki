// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2020 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.profile.input;

import java.util.Locale;
import java.util.Map;

import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cmscore.apps.CMS;

/**
 * This class implements the PKCS#12 password input for
 * Server-Side Keygen Enrollment
 * <p>
 *
 * @author Christina Fu
 */
public class ServerKeygenP12PasswordInput extends EnrollInput {

    public static final String P12PASSWORD = "serverSideKeygenEnrollP12Passwd";

    public ServerKeygenP12PasswordInput() {
        addValueName(P12PASSWORD);
    }

    /**
     * Initializes this default policy.
     */
    public void init(Profile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);
    }

    /**
     * Retrieves the localizable name of this policy.
     */
    public String getName(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_INPUT_SERVER_KEYGEN_P12PASSWORD_NAME");
    }

    /**
     * Retrieves the localizable description of this policy.
     */
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_INPUT_SERVER_KEYGEN_P12PASSWORD_TEXT");
    }

    public String getConfig(String name) {
        String config = super.getConfig(name);
        if (config == null || config.equals(""))
            return "true";
        return config;
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(Map<String, String> ctx, IRequest request) throws Exception {
        //
        logger.debug("ServerKeygenP12PasswordInput:populate: cfu");
    }

    /**
     * Retrieves the descriptor of the given value
     * parameter by name.
     */
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(P12PASSWORD)) {
            return new Descriptor(IDescriptor.SERVER_SIDE_KEYGEN_REQUEST_TYPE, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_SERVER_KEYGEN_P12PASSWORD"));
        }
        return null;
    }
}
