A friendly fork of https://spnego.sourceforge.net that contains separate artifacts for javax and jakarta style servlets.

Artifacts:
- `spnego-common`: everything that does not depend on a servlet API, in the package `com.eischet.spnego`: `SpnegoProvider`,
  the client `SpnegoHttpURLConnection`, `SpnegoPrincipal`, `Constants`, the access control classes and helpers.
- `spnego-javax`: the servlet classes for `javax.servlet`, in the package `com.eischet.spnego.javax`.
- `spnego-jakarta`: the servlet classes for `jakarta.servlet`, in the package `com.eischet.spnego.jakarta`.

Both servlet artifacts can be on the same class path, e.g. while an application moves from javax to jakarta.

Changes:
- (1.0) SOAP connections have been removed, under the assumption that these aren't needed with Kerberos in 2026+.
- (1.0) The packages have been renamed to avoid name clashes with the original project.
- (1.0) You can customize the error page sent to the client, see setErrorPage in BaseAuthenticator.
- (1.0.1) Logging has been changed to SLF4J. 
  The "spnego.logger.level" setting has been removed, just use the logging platforms standard facilities to configure logging.
  The loggers now use the class they log for, which makes it easier to find the source code for an error message in IDEs.
- (2.0.0) The servlet classes (`SpnegoAuthenticator`, `SpnegoHttpFilter`, `SpnegoFilterConfig`, `SpnegoHttpServletRequest`,
  `SpnegoHttpServletResponse`, `DelegateServletRequest`, and in jakarta also `SpnegoHttpSessionFilter` and `UserHttpSessionFilter`)
  have moved to the packages `com.eischet.spnego.javax` and `com.eischet.spnego.jakarta`. Before, both artifacts used
  `com.eischet.spnego` and hid each other's classes when they were on the same class path.
  `SpnegoProvider` and `SpnegoHttpURLConnection` do not depend on a servlet API and have moved to `spnego-common` (the jakarta
  version of `SpnegoHttpURLConnection`, with its more careful `dispose()`); `SpnegoProvider.getServerCredential` is public now.
  Update imports from `com.eischet.spnego.SpnegoAuthenticator` etc. to the new packages; classes of `spnego-common` keep their names.

Plans:
- Nullable/NonNull annotations will be added where appropriate.
- Code will be moved to the common module where possible.
- The javax and jakarta versions of `SpnegoHttpFilter` and `SpnegoAuthenticator` differ in small fixes (the jakarta filter checks the
  request URI for excluded directories and reports more errors at init; `isBlank` instead of `isEmpty`); they should be aligned.
