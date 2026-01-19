A friendly fork of https://spnego.sourceforge.net that contains separate artifacts for javax and jakarta style servlets.

Changes:
- SOAP connections have been removed, under the assumption that these aren't needed with Kerberos in 2026+.
- The packages have been renamed to avoid name clashes with the original project.
- You can customize the error page sent to the client, see setErrorPage in BaseAuthenticator.

Plans:
- Logging will be changed to SLF4J.
- Nullable/NonNull annotations will be added where appropriate.
- Code will be moved to the common module where possible.
