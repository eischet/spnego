A friendly fork of https://spnego.sourceforge.net that contains separate artifacts for javax and jakarta style servlets.

Changes:
- (1.0) SOAP connections have been removed, under the assumption that these aren't needed with Kerberos in 2026+.
- (1.0) The packages have been renamed to avoid name clashes with the original project.
- (1.0) You can customize the error page sent to the client, see setErrorPage in BaseAuthenticator.
- (1.1) Logging has been changed to SLF4J. 
  The "spnego.logger.level" setting has been removed, just use the logging platforms standard facilities to configure logging.
  The loggers now use the class they log for, which makes it easier to find the source code for an error message in IDEs.


Plans:
- Nullable/NonNull annotations will be added where appropriate.
- Code will be moved to the common module where possible.
