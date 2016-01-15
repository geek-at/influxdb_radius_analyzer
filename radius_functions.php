<?php
function translateAuth($t)
{
    switch($t)
    {
        case '1': return 'PAP';
        case '2': return 'CHAP';
        case '3': return 'MS-CHAP';
        case '4': return 'MS-CHAP v2';
        case '5': return 'EAP';
        case '7': return 'None';
        case '8': return 'Custom';
        default: return 'unknown: '.$t;
    }
}

/**
* Info from:
*  -https://technet.microsoft.com/en-us/library/cc771748(v=ws.10).aspx (Interpret NPS Database Format Log Files)
**/
function translateReason($t)
{
    switch($t)
    {
        case 0  : return 'IAS_SUCCESS';
        case 1  : return 'IAS_INTERNAL_ERROR';
        case 2  : return 'IAS_ACCESS_DENIED';
        case 3  : return 'IAS_MALFORMED_REQUEST';
        case 4  : return 'IAS_GLOBAL_CATALOG_UNAVAILABLE';
        case 5  : return 'IAS_DOMAIN_UNAVAILABLE';
        case 6  : return 'IAS_SERVER_UNAVAILABLE';
        case 7  : return 'IAS_NO_SUCH_DOMAIN';
        case 8  : return 'IAS_NO_SUCH_USER';
        case 16 : return 'IAS_AUTH_FAILURE';
        case 17 : return 'IAS_CHANGE_PASSWORD_FAILURE';
        case 18 : return 'IAS_UNSUPPORTED_AUTH_TYPE';
        case 32 : return 'IAS_LOCAL_USERS_ONLY';
        case 33 : return 'IAS_PASSWORD_MUST_CHANGE';
        case 34 : return 'IAS_ACCOUNT_DISABLED';
        case 35 : return 'IAS_ACCOUNT_EXPIRED';
        case 36 : return 'IAS_ACCOUNT_LOCKED_OUT';
        case 37 : return 'IAS_INVALID_LOGON_HOURS';
        case 38 : return 'IAS_ACCOUNT_RESTRICTION';
        case 48 : return 'IAS_NO_POLICY_MATCH';
        case 64 : return 'IAS_DIALIN_LOCKED_OUT';
        case 65 : return 'IAS_DIALIN_DISABLED';
        case 66 : return 'IAS_INVALID_AUTH_TYPE';
        case 67 : return 'IAS_INVALID_CALLING_STATION';
        case 68 : return 'IAS_INVALID_DIALIN_HOURS';
        case 69 : return 'IAS_INVALID_CALLED_STATION';
        case 70 : return 'IAS_INVALID_PORT_TYPE';
        case 71 : return 'IAS_INVALID_RESTRICTION';
        case 80 : return 'IAS_NO_RECORD';
        case 96 : return 'IAS_SESSION_TIMEOUT';
        case 97 : return 'IAS_UNEXPECTED_REQUEST';
        default: return translasteLongReason($t);
    }
}

/**
* Painfully parsed from
*  -https://technet.microsoft.com/en-us/library/dd197570(v=ws.10).aspx (NPS Reason Codes)
**/
function translasteLongReason($t)
{
    switch($t)
    {
        case '0': return 'The connection request was successfully authenticated and authorized by Network Policy Server.';
        case '1': return 'The connection request failed due to a Network Policy Server error.';
        case '2': return 'There are insufficient access rights to process the request.';
        case '3': return 'The Remote Authentication Dial-In User Service (RADIUS) Access-Request message that NPS received from the network access server was malformed.';
        case '4': return 'The NPS server was unable to access the Active Directory Domain Services (AD DS) global catalog. Because of this, authentication and authorization for the connection request cannot be performed, and access is denied.';
        case '5': return 'The Network Policy Server was unable to connect to a domain controller in the domain where the user account is located. Because of this, authentication and authorization for the connection request cannot be performed, and access is denied.';
        case '6': return 'The NPS server is unavailable. This issue can occur if the NPS server is running low on or is out of random access memory (RAM). It can also occur if the NPS server fails to receive the name of a domain controller, if there is a problem with the Security Accounts Manager (SAM) database on the local computer, or in circumstances where there is a Windows NT directory service (NTDS) failure.';
        case '7': return 'The domain that is specified in the User-Name attribute of the RADIUS message does not exist.';
        case '8': return 'The user account that is specified in the User-Name attribute of the RADIUS message does not exist.';
        case '9': return 'An Internet Authentication Service (IAS) extension dynamic link library (DLL) that is installed on the NPS server discarded the connection request.';
        case '10': return 'An IAS extension dynamic link library (DLL) that is installed on the NPS server has failed and cannot perform its function.';
        case '16': return 'Authentication failed due to a user credentials mismatch. Either the user name provided does not match an existing user account or the password was incorrect.';
        case '17': return 'The user\'s attempt to change their password has failed.';
        case '18': return 'The authentication method used by the client computer is not supported by Network Policy Server for this connection.';
        case '19': return 'Challenge Handshake Authentication Protocol (CHAP) is being used as the authentication method for the connection request, however CHAP is not configured to store a reversibly encrypted form of user passwords.
        With CHAP, reversibly encrypted password storage is required. You can enable reversibly encrypted password storage per user account or for all accounts in a domain using Group Policy. To enable reversibly encrypted password storage for a user account, obtain the properties of a user account in AD DS, click the Account tab, and then select the Store password using reversible encryption check box.
        To allow reversibly encrypted password storage for all user accounts in the domain, add the Group Policy Management Editor snap-in to the Microsoft Management Console (MMC) and enable the default domain policy setting Store password using reversible encryption at the following path: Computer Configuration | Policies | Windows Settings | Security Settings | Account Policies | Password Policies.';
        case '20': return 'The client attempted to use LAN Manager authentication, which is not supported by Network Policy Server. To enable the use of LAN Manager authentication, see NPS: LAN Manager Authentication.';
        case '21': return 'An IAS extension dynamic link library (DLL) that is installed on the NPS server rejected the connection request.';
        case '22': return 'Network Policy Server was unable to negotiate the use of an Extensible Authentication Protocol (EAP) type with the client computer.';
        case '23': return 'An error occurred during the Network Policy Server use of the Extensible Authentication Protocol (EAP). Check EAP log files for EAP errors. By default, these log files are located at %windir%\System32\Logfiles.';
        case '32': return 'NPS is joined to a workgroup and performs the authentication and authorization of connection requests using the local Security Accounts Manager database, however the Access-Request message contains a domain user name. NPS does not have access to a domain user accounts database. The connection request was denied.';
        case '33': return 'The user that is attempting to connect to the network must change their password.';
        case '34': return 'The user account that is specified in the RADIUS Access-Request message is disabled.';
        case '35': return 'The user account that is specified in the RADIUS Access-Request message is expired.';
        case '36': return 'The user\'s authentication attempts have exceeded the maximum allowed number of failed attempts specified by the Account lockout threshold setting in Account Lockout Policy in Group Policy. To unlock the account, obtain the user account properties in the Active Directory Users and Computers Microsoft Management Console (MMC) snap-in, click the Account tab, and then click Unlock account.';
        case '37': return 'According to AD DS user account logon hours, the user is not permitted to access the network on this day and time. To change the account logon hours, obtain the user account properties in the Active Directory Users and Computers snap-in, click the Account tab, and then click Logon Hours. In the Logon Hours dialog box, configure the days and times when the user is permitted to access the network.';
        case '38': return 'Authentication failed due to a user account restriction or requirement that was not followed. For example, the user account settings might require the use of a password but the user attempted to log on with a blank password. To resolve this issue, check the user account properties for restrictions, and then either remove or modify the restrictions or inform the user of the requirements for network access.';
        case '48': return 'The connection request did not match a configured network policy, so the connection request was denied by Network Policy Server.';
        case '49': return 'The connection request did not match a configured connection request policy, so the connection request was denied by Network Policy Server.';
        case '64': return 'Remote Access Account Lockout is enabled, and the user\'s authentication attempts have exceeded the designated lockout count because the credentials they supplied (\';user name and password) are not valid. When the lockout count for a user account is reset to 0 due to either a successful authentication or an automatic reset, the registry subkey for the user account is deleted. To manually reset a user account that has been locked out before the failed attempts counter is automatically reset, delete the following registry subkey that corresponds to the user\'s account name: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\AccountLockout\domain name:user name';
        case '65': return 'The Network Access Permission setting in the dial-in properties of the user account is set to Deny access to the user.
        To change the Network Access Permission setting to either Allow access or Control access through NPS Network Policy, obtain the properties of the user account in the Active Directory Users and Computers Microsoft Management Console (MMC) snap-in, click the Dial-in tab, and then change Network Access Permission.';
        case '66': return 'Authentication failed. Either the client computer attempted to use an authentication method that is not enabled on the matching network policy or the client Computer attempted to authenticate as Guest, but guest authentication is not enabled. To resolve this issue, ensure that all client computers are configured to use one or more authentication methods that are allowed by matching network policies.';
        case '67': return 'NPS denied the connection request because the value of the Calling-Station-ID attribute in the Access-Request message did not match the value of Verify Caller ID in user account dial-in properties in the Active Directory Users and Computers snap-in.';
        case '68': return 'The user or computer does not have permission to access the network on this day at this time. To change the day and time when the user is permitted to connect to the network, change the Day and Time Restrictions in the constraints of the matching network policy. For more information, see Constraints Properties.';
        case '69': return 'The telephone number of the network access server does not match the value of the Calling-Station-ID attribute that is configured in the constraints of the matching network policy. NPS denied the Access-Request message.';
        case '70': return 'The network access method used by the access client to connect to the network does not match the value of the NAS-Port-Type attribute that is configured in the constraints of the matching network policy. NPS denied the Access-Request message.';
        case '72': return 'The user password has expired or is about to expire and the user must change their password, however Authentication Methods in network policy constraints are not configured to allow the user to change their password. To allow the user to change their password, open the properties of the matching network policy, click the Constraints tab, click Authentication Methods, and then in the details pane select the appropriate authentication method and User can change password after it has expired check box.';
        case '73': return 'The purposes that are configured in the Application Policies extensions, also called Enhanced Key Usage (EKU) extensions, section of the user or computer certificate are not valid or are missing. The user or computer certificate must be configured with the Client Authentication purpose in Application Policies extensions. The object identifier for Client Authentication is 1.3.6.1.5.5.7.3.2. To correct this problem, you must reconfigure the certificate template with the Client Authentication purpose in Application Policies extensions, revoke the old certificate, and enroll a new certificate that is configured correctly. For more information, see Foundation Network Companion Guide: Deploying Computer and User Certificates at http://go.microsoft.com/fwlink/?LinkId=113884.';
        case '80': return 'NPS attempted to write accounting data to the data store (a log file on the local computer or a SQL Server database), but failed to do so for unknown reasons.';
        case '96': return 'Authentication failed due to an Extensible Authentication Protocol (EAP) session timeout; the EAP session with the access client was incomplete.';
        case '97': return 'The authentication request was not processed because it contained a Remote Authentication Dial-In User Service (RADIUS) message that was not appropriate for the secure authentication transaction.';
        case '112': return 'The local NPS proxy server forwarded a connection request to a remote RADIUS server, and the remote server rejected the connection request. Check the event log on the remote RADIUS server to determine the reason that the connection request was rejected.';
        case '113': return 'The local NPS proxy attempted to forward a connection request to a member of a remote RADIUS server group that does not exist. To resolve this issue, configure a valid remote RADIUS server group.';
        case '115': return 'The local NPS proxy did not forward a RADIUS message because it is not an accounting request or a connection request.';
        case '116': return 'The local NPS proxy server cannot forward the connection request to the remote RADIUS server because either the proxy cannot open a Windows socket over which to send the connection request, or the proxy server attempted to send the connection request but received Windows sockets errors that prevented successful completion of the send operation.';
        case '117': return 'The remote RADIUS server did not respond to the local NPS proxy within an acceptable time period. Verify that the remote RADIUS server is available and functioning properly.';
        case '118': return 'The local NPS proxy server received a RADIUS message that is malformed from a remote RADIUS server, and the message is unreadable. This issue can also be caused if a connection request contains more than the expected number of User-Name attributes, or if the User-Name attribute value is not valid, such as if the value has zero length or if it contains characters that are not valid.';
        case '256': return 'The certificate provided by the user or computer as proof of their identity is a revoked certificate. Because of this, the user or computer was not Authenticated, and NPS rejected the connection request.';
        case '257': return 'Due to a missing dynamic link library (DLL) or exported function, NPS cannot access the certificate revocation list to verify whether the user or client computer certificate is valid or is revoked.';
        case '258': return 'NPS cannot access the certificate revocation list to verify whether the user or client computer certificate is valid or is revoked. Because of this, authentication failed.';
        case '259': return 'The certification authority that manages the certificate revocation list is not available. NPS cannot verify whether the certificate is valid or is revoked. Because of this, authentication failed.';
        case '260': return 'The Extensible Authentication Protocol (EAP) message has been altered so that the Message Digest 5 (MD5) hash of the entire Remote Authentication Dial-In User Service (RADIUS) message does not match, or the message has been altered at the Schannel level.';
        case '261': return 'NPS cannot contact Active Directory Domain Services (AD DS) or the local user accounts database to perform authentication and authorization. The connection request is denied for this reason.';
        case '262': return 'NPS discarded the RADIUS message because it is incomplete and the signature was not verified.';
        case '263': return 'NPS did not receive complete credentials from the user or computer. The connection request is denied for this reason.';
        case '264': return 'The Security Support Provider Interface (SSPI) called by EAP reports that the system clocks on the NPS server and the access client are not synchronized.';
        case '265': return 'The certificate that the user or client computer provided to NPS as proof of identity chains to an enterprise root certification authority that is not trusted by the NPS server.';
        case '266': return 'NPS received a message that was either unexpected or incorrectly formatted. NPS discarded the message for this reason.';
        case '267': return 'The certificate provided by the connecting user or computer is not valid because it is not configured with the Client Authentication purpose in Application Policies or Enhanced Key Usage (EKU) extensions. NPS rejected the connection request for this reason.';
        case '268': return 'The certificate provided by the connecting user or computer is expired. NPS rejected the connection request for this reason.';
        case '269': return 'The Security Support Provider Interface (SSPI) called by EAP reports that the NPS server and the access client cannot communicate because they do not possess a common algorithm.';
        case '270': return 'Based on the matching NPS network policy, the user is required to log on with a smart card, but they have attempted to log on by using other credentials. NPS rejected the connection request for this reason.';
        case '271': return 'The connection request was not processed because the NPS server was in the process of shutting down or restarting when it received the request.';
        case '272': return 'The certificate that the user or client computer provided to NPS as proof of identity maps to multiple user or computer accounts rather than one account. NPS rejected the connection request for this reason.';
        case '273': return 'Authentication failed. NPS called Windows Trust Verification Services, and the trust provider is not recognized on this computer. A trust provider is a software module that implements the algorithm for application-specific policies regarding trust.';
        case '274': return 'Authentication failed. NPS called Windows Trust Verification Services, and the trust provider does not support the specified action. Each trust provider provides its own unique set of action identifiers. For information about the action identifiers supported by a trust provider, see the documentation for that trust provider.';
        case '275': return 'Authentication failed. NPS called Windows Trust Verification Services, and the trust provider does not support the specified form. A trust provider is a software module that implements the algorithm for application-specific policies regarding trust. Trust providers support subject forms that describe where the trust information is located and what trust actions to take regarding the subject.';
        case '276': return 'Authentication failed. NPS called Windows Trust Verification Services, but the binary file that calls EAP cannot be verified and is not trusted.';
        case '277': return 'Authentication failed. NPS called Windows Trust Verification Services, but the binary file that calls EAP is not signed, or the signer certificate cannot be found';
        case '278': return 'Authentication failed. The certificate that was provided by the connecting user or computer is expired.';
        case '279': return 'Authentication failed. The certificate is not valid because the validity periods of certificates in the chain do not match. For example, the following End Certificate and Issuer Certificate validity periods do not match: End Certificate validity period: 2007-2010; Issuer Certificate validity period: 2006-2008.';
        case '280': return 'Authentication failed. The certificate is not valid and was not issued by a valid certification authority (CA).';
        case '281': return 'Authentication failed. The path length constraint in the certification chain has been exceeded. This constraint restricts the maximum number of CA certificates that can follow this certificate in the certificate chain.';
        case '282': return 'Authentication failed. The certificate contains a critical extension that is unrecognized by NPS.';
        case '283': return 'Authentication failed. The certificate does not contain the Client Authentication purpose in Application Policies extensions, and cannot be used for authentication.';
        case '284': return 'Authentication failed. The certificate is not valid because the certificate issuer and the parent of the certificate in the certificate chain are required to match but do not match.';
        case '285': return 'Authentication failed. NPS cannot locate the certificate, or the certificate is incorrectly formed and is missing important information.';
        case '286': return 'Authentication failed. The certificate provided by the connecting user or computer is issued by a certification authority (CA) that is not trusted by the NPS server.';
        case '287': return 'Authentication failed. The certificate provided by the connecting user or computer does not chain to an enterprise root CA that NPS trusts.';
        case '288': return 'Authentication failed due to an unspecified trust failure.';
        case '289': return 'Authentication failed. The certificate provided by the connecting user or computer is revoked and is not valid.';
        case '290': return 'Authentication failed. A test or trial certificate is in use, however the test root CA is not trusted, according to local or domain policy settings.';
        case '291': return 'Authentication failed because NPS cannot locate and access the certificate revocation list to verify whether the certificate has or has not been revoked. This issue can occur if the revocation server is not available or if the certificate revocation list cannot be located in the revocation server database.';
        case '292': return 'Authentication failed. The value of the User-Name attribute in the connection request does not match the value of the common name (CN) property in the certificate.';
        case '293': return 'Authentication failed. The certificate provided by the connecting user or computer is not valid because it is not configured with the Client Authentication purpose in Application Policies or Enhanced Key Usage (EKU) extensions. NPS rejected the connection request for this reason.';
        case '294': return 'Authentication failed because the certificate was explicitly marked as untrusted by the Administrator. Certificates are designated as untrusted when they are imported into the Untrusted Certificates folder in the certificate store for the Current User or Local Computer in the Certificates Microsoft Management Console (MMC) snap-in.';
        case '295': return 'Authentication failed. The certificate provided by the connecting user or computer is issued by a CA that is not trusted by the NPS server.';
        case '296': return 'Authentication failed. The certificate provided by the connecting user or computer is not valid because it is not configured with the Client Authentication purpose in Application Policies or Enhanced Key Usage (EKU) extensions. NPS rejected the connection request for this reason.';
        case '297': return 'Authentication failed. The certificate provided by the connecting user or computer is not valid because it does not have a valid name.';
        case '298': return 'Authentication failed. Either the certificate does not contain a valid user principal name (UPN) or the value of the User-Name attribute in the connection request does not match the certificate.';
        case '299': return 'Authentication failed. The sequence of information provided by internal components or protocols during message verification is incorrect.';
        case '300': return 'Authentication failed. The certificate is malformed and Extensible Authentication Protocl (EAP) cannot locate credential information in the certificate.';
        case '301': return 'NPS terminated the authentication process. NPS received a cryptobinding type length value (TLV) from the access client that is not valid. This issue occurs when an attempt to breach your network security has occurred and a man-in-the-middle (MITM) attack is in progress. During MITM attacks on your network, attackers use unauthorized computers to intercept traffic between your legitimate hosts while posing as one of the legitimate hosts. The attacker\'s computer attempts to gain data from your other network resources. This enables the attacker to use the unauthorized computer to intercept, decrypt, and access all network traffic that would otherwise go to one of your legitimate network resources.';
        case '302': return 'NPS terminated the authentication process. NPS did not receive a required cryptobinding type length value (TLV) from the access client during the authentication process.';
    }
}

/**
* Info from:
*  -http://www.cisco.com/c/en/us/td/docs/net_mgmt/access_registrar/1-7/concepts/guide/radius.html (http://www.cisco.com/c/en/us/td/docs/net_mgmt/access_registrar/1-7/concepts/guide/radius.html)
*  -https://technet.microsoft.com/en-us/library/cc771748(v=ws.10).aspx (Interpret NPS Database Format Log Files)
*  -https://technet.microsoft.com/en-us/library/cc958030.aspx (RADIUS Packet Format)
**/
function translatePackageType($t)
{
    switch($t)
    {
        case '1': return 'Request';     //sent by the client (NAS) requesting access
        case '2': return 'Accepted ';   //sent by the RADIUS server allowing access
        case '3': return 'Rejected';    //sent by the RADIUS server rejecting access
        case '4': return 'Accounting-Request';  //sent by the client (NAS) requesting accounting
        case '5': return 'Accounting-Response'; //sent by the RADIUS server acknowledging accounting
        case '11': return 'Access-Challenge'; //sent by the RADIUS server requesting more information in order to allow access. The NAS, after communicating with the user, responds with another Access-Request.
        case '12': return 'Status-Server';
        case '13': return 'Status-Client';
        case '255': return 'Reserved';

        default: return 'unknown: '.$t;
    }
}