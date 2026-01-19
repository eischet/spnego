package com.eischet.spnego;

import org.jspecify.annotations.Nullable;

public abstract class AuthenticatorBase {

    protected @Nullable String errorPage;

    public @Nullable String getErrorPage() {
        return errorPage;
    }

    /**
     * Set the contents of the error page sent to the client when SC_UNAUTHORIZED is sent.
     * @param errorPage an error page, which may be null
     */
    public void setErrorPage(final @Nullable String errorPage) {
        this.errorPage = errorPage;
    }

}
