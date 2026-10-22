/**
 * Copyright (C) 2009 "Darwin V. Felix" <darwinfelix@users.sourceforge.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

package com.eischet.spnego;

import org.ietf.jgss.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import java.net.URL;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

/**
 * This is a Utility Class that can be used for finer grained control 
 * over message integrity, confidentiality and mutual authentication.
 *
 * <p>
 * This Class is exposed for developers who want to implement a custom 
 * HTTP client.
 * </p>
 *
 * <p>
 * Take a look at the {@link SpnegoHttpURLConnection} class and the 
 * {@code SpnegoHttpFilter} class (javax and jakarta artifacts) before attempting to implement your 
 * own HTTP client.
 * </p>
 *
 * <p>For more example usage, see the documentation at 
 * <a href="http://spnego.sourceforge.net" target="_blank">http://spnego.sourceforge.net</a>
 * </p>
 *
 * @author Darwin V. Felix
 *
 */
public class SpnegoProvider {

    /** Default LOGGER. */
    private static final Logger LOGGER = LoggerFactory.getLogger(SpnegoProvider.class);

    /** Factory for GSS-API mechanism. */
    private static final GSSManager MANAGER = GSSManager.getInstance();

    /** GSS-API mechanism "1.3.6.1.5.5.2". */
    private static final Oid SPNEGO_OID = SpnegoProvider.getOid();

    /*
     * This is a utility class (not a Singleton).
     */
    private SpnegoProvider() {
        // default private
    }

    /**
     * Returns the GSS-API interface for creating a security context.
     *
     * @param subject the person to be authenticated
     * @return GSSCredential to be used for creating a security context.
     * @throws PrivilegedActionException
     */
    public static GSSCredential getClientCredential(final Subject subject) throws PrivilegedActionException {

        final PrivilegedExceptionAction<GSSCredential> action = new PrivilegedExceptionAction<GSSCredential>() {
            public GSSCredential run() throws GSSException {
                return MANAGER.createCredential(null, GSSCredential.DEFAULT_LIFETIME, SpnegoProvider.SPNEGO_OID, GSSCredential.INITIATE_ONLY);
            }
        };

        return Subject.doAs(subject, action);
    }

    /**
     * Returns a GSSContext to be used by custom clients to set 
     * data integrity requirements, confidentiality and if mutual 
     * authentication is required.
     *
     * @param creds credentials of the person to be authenticated
     * @param url HTTP address of server (used for constructing a {@link GSSName}).
     * @return GSSContext 
     * @throws GSSException
     * @throws PrivilegedActionException
     */
    public static GSSContext getGSSContext(final GSSCredential creds, final URL url) throws GSSException {

        return MANAGER.createContext(SpnegoProvider.getServerName(url), SpnegoProvider.SPNEGO_OID, creds, GSSContext.DEFAULT_LIFETIME);
    }

    /**
     * Returns the {@link SpnegoAuthScheme} or null if header is missing.
     *
     * <p>
     * Throws UnsupportedOperationException if header is NOT Negotiate 
     * or Basic. 
     * </p>
     *
     * @param header ex. Negotiate or Basic
     * @return null if header missing/null else the auth scheme
     */
    public static SpnegoAuthScheme getAuthScheme(final String header) {

        if (null == header || header.isBlank()) {
            LOGGER.debug("authorization header was missing/null");
            return null;

        } else if (header.startsWith(Constants.NEGOTIATE_HEADER)) {
            final String token = header.substring(Constants.NEGOTIATE_HEADER.length() + 1);
            return new SpnegoAuthScheme(Constants.NEGOTIATE_HEADER, token);

        } else if (header.startsWith(Constants.BASIC_HEADER)) {
            final String token = header.substring(Constants.BASIC_HEADER.length() + 1);
            return new SpnegoAuthScheme(Constants.BASIC_HEADER, token);

        } else {
            throw new UnsupportedOperationException("Negotiate or Basic Only:" + header);
        }
    }

    /**
     * Returns the Universal Object Identifier representation of 
     * the SPNEGO mechanism.
     *
     * @return Object Identifier of the GSS-API mechanism
     */
    private static Oid getOid() {
        Oid oid = null;
        try {
            oid = new Oid("1.3.6.1.5.5.2");
        } catch (GSSException gsse) {
            LOGGER.error("Unable to create OID 1.3.6.1.5.5.2 !", gsse);
        }
        return oid;
    }

    /**
     * Returns the {@link GSSCredential} the server uses for pre-authentication.
     *
     * @param subject account server uses for pre-authentication
     * @return credential that allows server to authenticate clients
     * @throws PrivilegedActionException
     */
    public static GSSCredential getServerCredential(final Subject subject) throws PrivilegedActionException {

        final PrivilegedExceptionAction<GSSCredential> action = new PrivilegedExceptionAction<GSSCredential>() {
            public GSSCredential run() throws GSSException {
                return MANAGER.createCredential(null, GSSCredential.INDEFINITE_LIFETIME, SpnegoProvider.SPNEGO_OID, GSSCredential.ACCEPT_ONLY);
            }
        };
        return Subject.doAs(subject, action);
    }

    /**
     * Returns the {@link GSSName} constructed out of the passed-in 
     * URL object.
     *
     * @param url HTTP address of server
     * @return GSSName of URL.
     * @throws GSSException
     */
    private static GSSName getServerName(final URL url) throws GSSException {
        return MANAGER.createName("HTTP@" + url.getHost(), GSSName.NT_HOSTBASED_SERVICE, SpnegoProvider.SPNEGO_OID);
    }

    /**
     * Used by the BASIC Auth mechanism for establishing a LoginContext 
     * to authenticate a client/caller/request.
     *
     * @param username client username
     * @param password client password
     * @return CallbackHandler to be used for establishing a LoginContext
     */
    public static CallbackHandler getUsernamePasswordHandler(final String username, final String password) {

        LOGGER.debug("username={}", username);

        final CallbackHandler handler = new CallbackHandler() {
            public void handle(final Callback[] callback) {
                for (int i = 0; i < callback.length; i++) {
                    if (callback[i] instanceof NameCallback) {
                        final NameCallback nameCallback = (NameCallback) callback[i];
                        nameCallback.setName(username);
                    } else if (callback[i] instanceof PasswordCallback) {
                        final PasswordCallback passCallback = (PasswordCallback) callback[i];
                        passCallback.setPassword(password.toCharArray());
                    } else {
                        LOGGER.warn("Unsupported Callback i=" + i + "; class=" + callback[i].getClass().getName());
                    }
                }
            }
        };

        return handler;
    }
}
