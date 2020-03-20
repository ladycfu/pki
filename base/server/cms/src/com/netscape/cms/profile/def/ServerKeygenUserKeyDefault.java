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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.profile.def;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.util.Locale;
import java.util.Vector;
import java.security.KeyPair;
import java.security.PublicKey;

import netscape.security.provider.DSAPublicKey;
import netscape.security.provider.RSAPublicKey;
import netscape.security.x509.AlgorithmId;
import netscape.security.x509.CertificateX509Key;
import netscape.security.x509.X509CertInfo;
import netscape.security.x509.X509Key;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IEnrollProfile;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cmsutil.crypto.CryptoUtil;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;

/**
 * This class implements an enrollment default policy
 * that generates keys based on usre-supplied key type and size
 * then populates into the certificate template.
 *
 * @author Christina Fu
 */
public class ServerKeygenUserKeyDefault extends EnrollDefault {

    public static final String CONFIG_LEN = "keySize";
    public static final String CONFIG_TYPE = "keyType";
    public static final String VAL_LEN = "LEN";
    public static final String VAL_TYPE = "TYPE";

    public ServerKeygenUserKeyDefault() {
        super();
        addConfigName(CONFIG_TYPE);
        addConfigName(CONFIG_LEN);
        addValueName(VAL_TYPE);
        addValueName(VAL_LEN);
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);
    }

/*
    public void setConfig(String name, String value)
            throws EPropertyException {
        super.setConfig(name, value);
    }
*/

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_TYPE)) {
            return new Descriptor(IDescriptor.STRING,
                    null,
                    "RSA",
                    CMS.getUserMessage(locale,
                            "CMS_PROFILE_SERVER_KEYGEN_KEYTYPE"));
        } else if (name.equals(CONFIG_LEN)) {
            return new Descriptor(IDescriptor.STRING,
                    null,
                    "2048",
                    CMS.getUserMessage(locale,
                            "CMS_PROFILE_SERVER_KEYGEN_KEYSIZE"));
        } else  {
            return null;
        }
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_LEN)) {
            return new Descriptor(IDescriptor.STRING,
                    IDescriptor.READONLY,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_KEY_LEN"));
        } else if (name.equals(VAL_TYPE)) {
            return new Descriptor(IDescriptor.STRING,
                    IDescriptor.READONLY,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_KEY_TYPE"));
        } else {
            return null;
        }
    }

    public void setValue(String name, Locale locale,
            X509CertInfo info, String value)
            throws EPropertyException {
        // this default rule is readonly
    }

    public String getValue(String name, Locale locale,
            X509CertInfo info)
            throws EPropertyException {
        CMS.debug("ServerKeygenUserKeyDefault: getValue name=" + name);
        if (name == null) {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }

        if (name.equals(VAL_LEN)) {
            CertificateX509Key ck = null;

            try {
                ck = (CertificateX509Key)
                        info.get(X509CertInfo.KEY);
            } catch (Exception e) {
                // nothing
            }
            X509Key k = null;

            try {
                k = (X509Key)
                        ck.get(CertificateX509Key.KEY);
            } catch (Exception e) {
                // nothing
            }
            if (k == null) {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_PROFILE_KEY_NOT_FOUND"));
            }
            try {
                if (k.getAlgorithm().equals("RSA")) {
                    return Integer.toString(getRSAKeyLen(k));
                } else if (k.getAlgorithm().equals("EC")) {
                    Vector<String> vect = CryptoUtil.getECKeyCurve(k);
                    if (vect != null)
                        return vect.toString();
                    else
                        return null;
                } else {
                    return Integer.toString(getDSAKeyLen(k));
                }
            } catch (Exception e) {
                CMS.debug("ServerKeygenUserKeyDefault: getValue " + e.toString());
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }
        } else if (name.equals(VAL_TYPE)) {
            CertificateX509Key ck = null;

            try {
                ck = (CertificateX509Key)
                        info.get(X509CertInfo.KEY);
            } catch (Exception e) {
                // nothing
            }
            X509Key k = null;

            try {
                k = (X509Key)
                        ck.get(CertificateX509Key.KEY);
            } catch (Exception e) {
                // nothing
            }
            if (k == null) {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_PROFILE_KEY_NOT_FOUND"));
            }
            return k.getAlgorithm() + " - " +
                    k.getAlgorithmId().getOID().toString();
        } else {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getText(Locale locale) {
        String params[] = {
                getConfig(CONFIG_TYPE),
                getConfig(CONFIG_LEN)
            };
        CMS.debug("ServerKeygenUserKeyDefault: getText ");
        if (locale == null)
            CMS.debug("ServerKeygenUserKeyDefault: getText: locale null ");

        return CMS.getUserMessage(locale, "CMS_PROFILE_DEF_SERVER_KEYGEN_USER_KEY_INFO", params);
    }

    public int getRSAKeyLen(X509Key key) throws Exception {
        X509Key newkey = null;

        try {
            newkey = new X509Key(AlgorithmId.get("RSA"),
                        key.getKey());
        } catch (Exception e) {
            CMS.debug("ServerKeygenUserKeyDefault: getRSAKey " + e.toString());
            throw e;
        }
        RSAPublicKey rsaKey = new RSAPublicKey(newkey.getEncoded());

        return rsaKey.getKeySize();
    }

    public int getDSAKeyLen(X509Key key) throws Exception {
        // Check DSAKey parameters.
        // size refers to the p parameter.
        DSAPublicKey dsaKey = new DSAPublicKey(key.getEncoded());
        DSAParams keyParams = dsaKey.getParams();
        BigInteger p = keyParams.getP();
        int len = p.bitLength();

        return len;
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IRequest request, X509CertInfo info)
            throws EProfileException {
        CertificateX509Key certKey = null;
        CMS.debug("ServerKeygenUserKeyDefault: populate: in here");
        // cfu TODO: trigger serverSide keygen
        // the key from request into x509 certinfo
        try {
            request.setExtData("isServerSideKeygen", "true");
//            cfu test pubKey
            CryptoManager cm = CryptoManager.getInstance();
            CryptoToken token = cm.getInternalKeyStorageToken();
            String keySizeStr = request.getExtDataInString("keySize");
            int keySize = 2048;
            if (keySizeStr != null) {
                CMS.debug("ServerKeygenUserKeyDefault: populate: keySize in request: " + keySizeStr);
                keySize = Integer.parseInt(keySizeStr);
            } else {
                CMS.debug("ServerKeygenUserKeyDefault: populate: keySize in request null;  default to 2048");
            }
            KeyPair pair = CryptoUtil.generateRSAKeyPair(token, keySize, true);
            PublicKey pubKey = pair.getPublic();
//            byte[] certKeyData = request.getExtDataInByteArray(IEnrollProfile.REQUEST_KEY);
            byte[] certKeyData = pubKey.getEncoded();
            if (certKeyData != null) {
                certKey = new CertificateX509Key(
                        new ByteArrayInputStream(certKeyData));
            } else {
                CMS.debug("ServerKeygenUserKeyDefault: populate: serverKeygen to be implemented ");
            }
            info.set(X509CertInfo.KEY, certKey);
        } catch (Exception e) {
            CMS.debug("ServerKeygenUserKeyDefault: populate " + e.toString());
        }
    }
}
