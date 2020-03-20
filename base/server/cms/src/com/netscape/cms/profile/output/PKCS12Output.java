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
package com.netscape.cms.profile.output;

import java.io.ByteArrayOutputStream;
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.Map;

import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileContext;
import com.netscape.certsrv.profile.IProfileOutput;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.common.EnrollProfile;

/**
 * This class implements the output plugin that outputs
 * PKCS12 response for the issued certificate for Server-side keygen enrollment.
 *
 * Christina Fu
 */
public class PKCS12Output extends EnrollOutput {

    public static final String VAL_P12_RESPONSE = "p12_response";

    public PKCS12Output() {
        addValueName(VAL_P12_RESPONSE);
    }

    /**
     * Retrieves the localizable name of this policy.
     */
    public String getName(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_OUTPUT_PKCS12");
    }

    /**
     * Retrieves the localizable description of this policy.
     */
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_OUTPUT_PKCS12_TEXT");
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IProfileContext ctx, IRequest request)
            throws EProfileException {
    }

    /**
     * Retrieves the descriptor of the given value
     * parameter by name.
     */
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_P12_RESPONSE)) {
            return new Descriptor(IDescriptor.SERVER_SIDE_KEYGEN_PKCS12, null,
                    null,
                    CMS.getUserMessage(locale,
                            "CMS_PROFILE_OUTPUT_PKCS12"));
        }
        return null;
    }

    public String getValue(String name, Locale locale, IRequest request)
            throws EProfileException {
        String testP12 =
            "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";

        if (name.equals(VAL_P12_RESPONSE)) {
            try {
                byte pkcs12[] = request.getExtDataInByteArray(
                        EnrollProfile.REQUEST_ISSUED_P12);
                if (pkcs12 == null) {
                    //return null;
                    //test
                    return testP12;
                }

/* cfu:
When it gets to the actual response, we need to do something like this when we get there:
    HttpServletResponse resp = cmsReq.getHttpResp();
    resp.setContentType("application/x-pkcs12");
    resp.getOutputStream().write(pkcs12);
*/
                return Utils.base64encode(pkcs12, true);
            } catch (Exception e) {
                return null;
            }
        } else {
            return null;
        }
    }

}
