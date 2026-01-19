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

import java.io.IOException;
import java.util.logging.Logger;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

/**
 * Be sure to specify this <b>BEFORE</b> the <code>UserHttpSessionFilter</code>.
 * 
 * @author Darwin V. Felix
 *
 */
public class SpnegoHttpSessionFilter implements Filter {
    
    /** logger. */
    private static final Logger LOGGER = Logger.getLogger(SpnegoHttpSessionFilter.class.getName());
    
    private String httpSessAttribName = "spnegoAuthNuser";
    
    private final transient SpnegoHttpFilter spnego = new SpnegoHttpFilter();

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
        LOGGER.info("SpnegoHttpSessionFilter::init");
        this.spnego.init(filterConfig);
        final String tmp = filterConfig.getInitParameter("http.sess.attib.name");
        if (null != tmp && !tmp.isBlank()) {
            httpSessAttribName = tmp;
        }
    }
    
    @Override
    public void destroy() {
        this.spnego.destroy();
    }

    @Override
    public void doFilter(final ServletRequest request
        , final ServletResponse response, final FilterChain chain) 
        throws IOException, ServletException {
        
        final HttpServletRequest httpRequest = (HttpServletRequest) request;
        
        final HttpSession httpSession = httpRequest.getSession(false);

        // implement your own rules/logic. for this example
        // only perform Kerberos auth if http session does not exist
        if (null == httpSession || null == httpSession.getAttribute(httpSessAttribName)) {
            LOGGER.fine("SpnegoHttpSessionFilter::doFilter no session");
            this.spnego.doFilter(request, response, chain);
        } else {
            LOGGER.fine("SpnegoHttpSessionFilter::doFilter HAS session");
            chain.doFilter(request, response);
        }
    }
}

