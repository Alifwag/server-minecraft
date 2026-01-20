
package org.jboss.security;

import java.io.IOException;
import java.io.Serializable;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.KeyException;
import java.security.ProviderException;
import java.util.Arrays;
import java.util.List;
import javax.annotation.Generated;
import javax.management.AttributeNotFoundException;
import javax.naming.NamingException;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.xml.stream.Location;
import javax.xml.stream.XMLStreamException;


/**
 * Warning this class consists of generated code.
 * 
 */
@Generated(value = "org.jboss.logging.processor.model.MessageBundleImplementor", date = "2014-11-11T23:27:01-0200")
public class PicketBoxMessages_$bundle
    implements Serializable, PicketBoxMessages
{

    private final static long serialVersionUID = 1L;
    private final static String projectCode = "PBOX";
    public final static PicketBoxMessages_$bundle INSTANCE = new PicketBoxMessages_$bundle();
    private final static String unableToStoreKeyStoreToFile = "Unable to store keystore to file (%s)";
    private final static String unexpectedSecurityDomainInContext = "The context security domain does not match expected domain %s";
    private final static String failedToObtainInfoFromAppPolicy = "Application policy has no info of type %s";
    private final static String failedToCreatePrincipal = "Failed to create principal: %s";
    private final static String failedToValidateURL = "Failed to validate %s as a URL, file or classpath resource";
    private final static String invalidBase64String = "Invalid Base64 string: %s";
    private final static String failedToGetTransactionManager = "Unable to get TransactionManager";
    private final static String failedToObtainPassword = "Failed to obtain the password";
    private final static String invalidNullBaseContextDN = "Invalid configuration: baseCtxDN is null";
    private final static String failedToObtainAuthenticationInfo = "AuthenticationInfo not set in security domain %s";
    private final static String missingCallerInfoMessage = "Either caller subject or caller run-as should be non-null";
    private final static String failedToObtainSecDomainFromContextOrConfig = "Failed to obtain security domain from security context or configuration";
    private final static String invalidKeyFormat = "Invalid key format: %s";
    private final static String invalidDelegateMapEntry = "Invalid delegate map entry: %s";
    private final static String failedToParseJACCStatesConfigFile = "Failed to parse jacc-policy-config-states.xml";
    private final static String unableToWriteVaultDataFileMessage = "Unable to write vault data file (%s)";
    private final static String failedToInstantiateDelegateModule = "Failed to instantiate delegate module %s";
    private final static String unableToParseReferralAbsoluteName = "Unable to parse referral absolute name: %s";
    private final static String vaultNotInitializedMessage = "Vault is not initialized";
    private final static String unexpectedSecurityDomainInInfo = "Application policy -> %s does not match expected security domain %s";
    private final static String invalidNullOrEmptyOptionMap = "Options map %s is null or empty";
    private final static String unexpectedNamespace = "Unexpected namespace %s encountered";
    private final static String failedToInstantiateClassMessage = "Failed to instantiate %s class";
    private final static String unableToFindSchema = "Unable to find schema file %s";
    private final static String identityTypeFactoryNotImplemented = "IdentityFactory for type %s not implemented";
    private final static String noPolicyContextForIdMessage = "No PolicyContext exists for contextID %s";
    private final static String pbeUtilsMessage = "Ecrypt a password using the JaasSecurityDomain password\n\nUsage: PBEUtils salt count domain-password password\n  salt : the Salt attribute from the JaasSecurityDomain\n  count : the IterationCount attribute from the JaasSecurityDomain\n  domain-password : the plaintext password that maps to the KeyStorePass attribute from the JaasSecurityDomain\n  password : the plaintext password that should be encrypted with the JaasSecurityDomain password\n";
    private final static String failedToFindResource = "Failed to find resource %s";
    private final static String unableToFollowReferralForAuth = "Unable to follow referral for authentication: %s";
    private final static String enterUsernameMessage = "Enter the username: ";
    private final static String missingRequiredAttributes = "Missing required attribute(s): %s";
    private final static String missingSystemProperty = "The specified system property %s is missing";
    private final static String failedToDecodeBindCredential = "Failed to decode bindCredential";
    private final static String unableToLoadPropertiesFile = "Properties file %s not available for loading";
    private final static String failedToObtainSHAMessageDigest = "Failed to obtain SHA MessageDigest";
    private final static String failedToResolveTargetStateMessage = "Failed to resolve target state %s for transition %s";
    private final static String unableToCreateVaultMessage = "Unable to instantiate vault class";
    private final static String missingDelegateForLayer = "Delegate is missing for layer %s";
    private final static String invalidKeystorePasswordFormatMessage = "Keystore password should be either masked or prefixed with one of {EXT}, {EXTC}, {CMD}, {CMDC}, {CLASS}";
    private final static String invalidThreadContextClassLoader = "Thread context classloader has not been set";
    private final static String failedToCreateSealedObject = "Failed to create SealedObject";
    private final static String noMatchForAliasMessage = "No match for alias %s, existing aliases: %s";
    private final static String unsupportedQOP = "Unsupported quality of protection: %s";
    private final static String invalidSecurityAnnotationConfig = "Invalid annotation configuration: either @SecurityConfig or @Authentication is needed";
    private final static String failedToLookupDataSourceMessage = "Error looking up DataSource from %s";
    private final static String missingXACMLPolicyForContextId = "Missing XACML policy for contextID %s";
    private final static String sharedKeyMismatchMessage = "Vault mismatch: shared key does not match for vault block %s and attribute name %s";
    private final static String deniedByIdentityTrustMessage = "Caller denied by identity trust framework";
    private final static String invalidLoginModuleStackRef = "auth-module references a login module stack that doesn't exist: %s";
    private final static String unableToGetPrincipalOrCredsForAssociation = "Unable to get the calling principal or its credentials for resource association";
    private final static String invalidType = "Class is not an instance of %s";
    private final static String missingServiceAuthToken = "JSSE domain %s has been requested to provide sensitive security information, but no service authentication token has been configured on it. Use setServiceAuthToken()";
    private final static String filePasswordUsageMessage = "Write a password in opaque form to a file for use with the FilePassword accessor\n\nUsage: FilePassword salt count password password-file\n  salt  : an 8 char sequence for PBEKeySpec\n  count : iteration count for PBEKeySpec\n  password : the clear text password to write\n  password-file : the path to the file to write the password to\n";
    private final static String unableToEncryptDataMessage = "Unable to encrypt data";
    private final static String unableToInitializeLoginContext = "Unable to initialize login context";
    private final static String invalidNullSecurityContext = "Unable to proceed: security context is null";
    private final static String invalidNullKeyStoreURL = "Cannot load KeyStore of type %s: required keyStoreURL is null";
    private final static String noSecretKeyandAliasAlreadyUsed = "There is no SecretKey under the alias (%s) and the alias is already used to denote diffrent crypto object in the keystore.";
    private final static String unexpectedElement = "Unexpected element %s encountered";
    private final static String invalidPasswordType = "Invalid password type: %s";
    private final static String cacheValidationFailedMessage = "Cache validation failed";
    private final static String missingPropertiesFile = "Missing properties file: %s";
    private final static String base64EncoderMessage = "Usage: Base64Encoder <string> <optional hash algorithm>";
    private final static String invalidPermissionChecks = "Permission checks must be different";
    private final static String unableToFindSetSecurityInfoMessage = "Unable to find setSecurityInfo(Principal, Object) in CallbackHandler";
    private final static String invalidEJBVersion = "Invalid EJB version: %s";
    private final static String sizeMismatchMessage = "Size mismatch between %s and %s";
    private final static String missingXMLUserRolesMapping = "Missing XML configuration for user/roles mapping";
    private final static String failedToObtainAuthorizationInfo = "AuthorizationInfo not set in security domain %s";
    private final static String failedToObtainUsername = "Failed to obtain the username";
    private final static String failedToMatchCredential = "Supplied credential did not match existing credential for alias %s";
    private final static String invalidVaultStringFormat = "Invalid vaultString format: %s";
    private final static String invalidNullAuthConfigProviderForLayer = "AuthConfigProvider is null for layer %s, contextID: %s";
    private final static String noMatchingRoleFoundInDescriptor = "No matching role found in deployment descriptor for role %s";
    private final static String cacheMissMessage = "Cache miss";
    private final static String unableToCreateACLPersistenceStrategy = "Failed to instantiate persistence strategy class";
    private final static String unrecognizedVaultContentVersion = "Unrecognized security vault content version (%s), expecting (from %s to %s)";
    private final static String failedToRetrieveCertificateMessage = "Failed to retrieve certificate from keystore using alias %s";
    private final static String unableToInitSecurityFactory = "Unable to initialize security factory";
    private final static String invalidPassword = "Password invalid/Password required";
    private final static String unableToWriteShareKeyFileMessage = "Unable to write shared key file";
    private final static String unableToGetCertificateFromClass = "Unable to obtain a X509Certificate from %s";
    private final static String existingCredentialMessage = "Existing credential: ";
    private final static String unableToLoadVaultMessage = "Unable to load vault class";
    private final static String failedToProcessQueryMessage = "Error processing query";
    private final static String illegalBase64Character = "Illegal Base64 character";
    private final static String unableToFindPropertiesFile = "Properties file %s not found";
    private final static String identityTrustValidationFailedMessage = "Identity trust validation failed";
    private final static String vaultDoesnotContainSecretKey = "Security Vault does not contain SecretKey entry under alias (%s)";
    private final static String noMatchingUsernameFoundInPrincipals = "No matching username found in principals";
    private final static String noCallbackHandlerAvailable = "No CallbackHandler available to collect authentication information";
    private final static String missingAdminKeyInOriginalVaultData = "Security Vault conversion unsuccessful missing admin key in original vault data";
    private final static String missingRequiredModuleOptionMessage = "Missing required module option: %s";
    private final static String noServerAuthModuleForRequestType = "No ServerAuthModule configured to support type %s";
    private final static String failedToObtainApplicationPolicy = "Failed to obtain ApplicationPolicy for domain %s";
    private final static String invalidUnmaskedKeystorePasswordMessage = "Keystore password is not masked";
    private final static String unableToLocateMBeanServer = "Unable to locate MBean server";
    private final static String fileOrDirectoryDoesNotExistMessage = "File or directory %s does not exist";
    private final static String invalidControlFlag = "Invalid control flag: %s";
    private final static String invalidPolicyRegistrationType = "Unsupported policy registration type: %s";
    private final static String nullRolesInSubjectMessage = "Subject contains a null set of roles";
    private final static String unableToGetPasswordFromVault = "Unable to get password value from vault";
    private final static String unableToGetKeyStore = "Unable to get keystore (%s)";
    private final static String failedToRegisterAuthConfigProvider = "Failed to register AuthConfigProvider %s";
    private final static String invalidNullTransactionManager = "Invalid null TransactionManager";
    private final static String callbackHandlerSysPropertyNotSet = "CallbackHandler not specified by system property %s";
    private final static String unableToLookupDataSource = "Unable to lookup DataSource - the DS JNDI name is null";
    private final static String authenticationFailedMessage = "Access denied: authentication failed";
    private final static String failedToCreateDocumentBuilder = "Failed to create DocumentBuilder";
    private final static String failedToInvokeCallbackHandler = "Failed to invoke CallbackHandler";
    private final static String unsupportedAlgorithm = "Unsupported algorithm: %s";
    private final static String aclEntryPermissionAlreadySet = "ACLEntry permission has already been set";
    private final static String noMatchingUsernameFoundInRoles = "No matching username found in roles";
    private final static String failedToRetrievePublicKeyMessage = "Failed to retrieve public key from keystore using alias %s";
    private final static String invalidNullProperty = "The property %s is null";
    private final static String unableToLocateACLForResourceMessage = "Unable to locate ACL for resource %s";
    private final static String invalidNullOrEmptyOptionMessage = "Option %s is null or empty";
    private final static String invalidTransitionForActionMessage = "No transition for action %s from state %s ";
    private final static String malformedIdentityString = "Malformed identity string: %s. Expected Identity_Class:Identity_Name";
    private final static String failedToVerifyServiceAuthToken = "Service authentication token verification failed";
    private final static String invalidNullLoginConfig = "'java.security.auth.login.config' system property not set and auth.conf file not present";
    private final static String authorizationFailedMessage = "Acces denied: authorization failed";
    private final static String moduleAbortFailedMessage = "Invocation of abort on module failed";
    private final static String invalidSharedKeyMessage = "The shared key is invalid or has been incorrectly encoded";
    private final static String invalidDirectoryFormatMessage = "Directory %s does not end with / or \\";
    private final static String invalidPasswordCommandType = "Invalid password command type: %s";
    private final static String failedToMatchStrings = "Failed to match %s and %s";
    private final static String aclResourceAlreadySet = "ACL resource has already been set";
    private final static String failedToFindNamespaceURI = "Failed to find namespace URI for %s";
    private final static String invalidNullArgument = "Argument %s cannot be null";
    private final static String moduleCommitFailedMessage = "Invocation of commit on module failed";
    private final static String mixedVaultDataFound = "Security Vault contains both covnerted (%s) and pre-conversion data (%s), failed to load vault";
    private final static String enterPasswordMessage = "Enter the password: ";
    private final static String suppliedCredentialMessage = "Supplied credential: ";
    private final static String failedToCreateSecretKeySpec = "Failed to create SecretKeySpec from session key";
    private final static String unableToLocateACLWithNoStrategyMessage = "Unable to locate ACL: persistence strategy has not been set";
    private final static String failedToFindBaseContextDN = "Search for context %s found no results";
    private final static String unableToHandleCallback = "%s does not handle a callback of type %s";
    private final static String invalidMBeanAttribute = "%s is not an MBean attribute";
    private final static String unexpectedAttribute = "Unexpected attribute %s encountered";
    private final static String unableToFindPrincipalInDB = "No matching principal found in DB: %s";
    private final static String operationNotAllowedMessage = "Operation not allowed";
    private final static String unexpectedExceptionDuringSecretKeyCreation = "Unexpected exception during SecretKeySpec creation";

    protected PicketBoxMessages_$bundle() {
    }

    protected PicketBoxMessages_$bundle readResolve() {
        return INSTANCE;
    }

    @Override
    public final RuntimeException unableToStoreKeyStoreToFile(final Throwable throwable, final String file) {
        RuntimeException result = new RuntimeException(String.format(((projectCode +"000139: ")+ unableToStoreKeyStoreToFile$str()), file), throwable);
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String unableToStoreKeyStoreToFile$str() {
        return unableToStoreKeyStoreToFile;
    }

    @Override
    public final IllegalArgumentException unexpectedSecurityDomainInContext(final String securityDomain) {
        IllegalArgumentException result = new IllegalArgumentException(String.format(((projectCode +"000103: ")+ unexpectedSecurityDomainInContext$str()), securityDomain));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String unexpectedSecurityDomainInContext$str() {
        return unexpectedSecurityDomainInContext;
    }

    @Override
    public final IllegalStateException failedToObtainInfoFromAppPolicy(final String infoType) {
        IllegalStateException result = new IllegalStateException(String.format(((projectCode +"000097: ")+ failedToObtainInfoFromAppPolicy$str()), infoType));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String failedToObtainInfoFromAppPolicy$str() {
        return failedToObtainInfoFromAppPolicy;
    }

    @Override
    public final LoginException failedToCreatePrincipal(final String message) {
        LoginException result = new LoginException(String.format(((projectCode +"000051: ")+ failedToCreatePrincipal$str()), message));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String failedToCreatePrincipal$str() {
        return failedToCreatePrincipal;
    }

    @Override
    public final MalformedURLException failedToValidateURL(final String urlString) {
        MalformedURLException result = new MalformedURLException(String.format(((projectCode +"000114: ")+ failedToValidateURL$str()), urlString));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String failedToValidateURL$str() {
        return failedToValidateURL;
    }

    @Override
    public final IllegalArgumentException invalidBase64String(final String base64Str) {
        IllegalArgumentException result = new IllegalArgumentException(String.format(((projectCode +"000112: ")+ invalidBase64String$str()), base64Str));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String invalidBase64String$str() {
        return invalidBase64String;
    }

    @Override
    public final RuntimeException failedToGetTransactionManager(final Throwable throwable) {
        RuntimeException result = new RuntimeException(String.format(((projectCode +"000060: ")+ failedToGetTransactionManager$str())), throwable);
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String failedToGetTransactionManager$str() {
        return failedToGetTransactionManager;
    }

    @Override
    public final SecurityException failedToObtainPassword(final Throwable throwable) {
        SecurityException result = new SecurityException(String.format(((projectCode +"000032: ")+ failedToObtainPassword$str())), throwable);
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String failedToObtainPassword$str() {
        return failedToObtainPassword;
    }

    @Override
    public final NamingException invalidNullBaseContextDN() {
        NamingException result = new NamingException(String.format(((projectCode +"000036: ")+ invalidNullBaseContextDN$str())));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String invalidNullBaseContextDN$str() {
        return invalidNullBaseContextDN;
    }

    @Override
    public final IllegalStateException failedToObtainAuthenticationInfo(final String securityDomain) {
        IllegalStateException result = new IllegalStateException(String.format(((projectCode +"000049: ")+ failedToObtainAuthenticationInfo$str()), securityDomain));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String failedToObtainAuthenticationInfo$str() {
        return failedToObtainAuthenticationInfo;
    }

    @Override
    public final String missingCallerInfoMessage() {
        String result = String.format(((projectCode +"000100: ")+ missingCallerInfoMessage$str()));
        return result;
    }

    protected String missingCallerInfoMessage$str() {
        return missingCallerInfoMessage;
    }

    @Override
    public final IllegalStateException failedToObtainSecDomainFromContextOrConfig() {
        IllegalStateException result = new IllegalStateException(String.format(((projectCode +"000047: ")+ failedToObtainSecDomainFromContextOrConfig$str())));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String failedToObtainSecDomainFromContextOrConfig$str() {
        return failedToObtainSecDomainFromContextOrConfig;
    }

    @Override
    public final RuntimeException invalidKeyFormat(final String key) {
        RuntimeException result = new RuntimeException(String.format(((projectCode +"000044: ")+ invalidKeyFormat$str()), key));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String invalidKeyFormat$str() {
        return invalidKeyFormat;
    }

    @Override
    public final IllegalStateException invalidDelegateMapEntry(final String entry) {
        IllegalStateException result = new IllegalStateException(String.format(((projectCode +"000079: ")+ invalidDelegateMapEntry$str()), entry));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String invalidDelegateMapEntry$str() {
        return invalidDelegateMapEntry;
    }

    @Override
    public final IllegalStateException failedToParseJACCStatesConfigFile(final Throwable throwable) {
        IllegalStateException result = new IllegalStateException(String.format(((projectCode +"000094: ")+ failedToParseJACCStatesConfigFile$str())), throwable);
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String failedToParseJACCStatesConfigFile$str() {
        return failedToParseJACCStatesConfigFile;
    }

    @Override
    public final String unableToWriteVaultDataFileMessage(final String fileName) {
        String result = String.format(((projectCode +"000130: ")+ unableToWriteVaultDataFileMessage$str()), fileName);
        return result;
    }

    protected String unableToWriteVaultDataFileMessage$str() {
        return unableToWriteVaultDataFileMessage;
    }

    @Override
    public final LoginException failedToInstantiateDelegateModule(final String loginModuleName) {
        LoginException result = new LoginException(String.format(((projectCode +"000068: ")+ failedToInstantiateDelegateModule$str()), loginModuleName));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String failedToInstantiateDelegateModule$str() {
        return failedToInstantiateDelegateModule;
    }

    @Override
    public final RuntimeException unableToParseReferralAbsoluteName(final URISyntaxException cause, final String absoluteName) {
        RuntimeException result = new RuntimeException(String.format(((projectCode +"000141: ")+ unableToParseReferralAbsoluteName$str()), absoluteName), cause);
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String unableToParseReferralAbsoluteName$str() {
        return unableToParseReferralAbsoluteName;
    }

    @Override
    public final String vaultNotInitializedMessage() {
        String result = String.format(((projectCode +"000008: ")+ vaultNotInitializedMessage$str()));
        return result;
    }

    protected String vaultNotInitializedMessage$str() {
        return vaultNotInitializedMessage;
    }

    @Override
    public final IllegalStateException unexpectedSecurityDomainInInfo(final String infoType, final String securityDomain) {
        IllegalStateException result = new IllegalStateException(String.format(((projectCode +"000098: ")+ unexpectedSecurityDomainInInfo$str()), infoType, securityDomain));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String unexpectedSecurityDomainInInfo$str() {
        return unexpectedSecurityDomainInInfo;
    }

    @Override
    public final IllegalArgumentException invalidNullOrEmptyOptionMap(final String mapName) {
        IllegalArgumentException result = new IllegalArgumentException(String.format(((projectCode +"000120: ")+ invalidNullOrEmptyOptionMap$str()), mapName));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String invalidNullOrEmptyOptionMap$str() {
        return invalidNullOrEmptyOptionMap;
    }

    @Override
    public final XMLStreamException unexpectedNamespace(final String namespaceURI, final Location location) {
        XMLStreamException result = new XMLStreamException(String.format(((projectCode +"000088: ")+ unexpectedNamespace$str()), namespaceURI), location);
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String unexpectedNamespace$str() {
        return unexpectedNamespace;
    }

    @Override
    public final String failedToInstantiateClassMessage(final Class clazz) {
        String result = String.format(((projectCode +"000071: ")+ failedToInstantiateClassMessage$str()), clazz);
        return result;
    }

    protected String failedToInstantiateClassMessage$str() {
        return failedToInstantiateClassMessage;
    }

    @Override
    public final RuntimeException unableToFindSchema(final String schemaFile) {
        RuntimeException result = new RuntimeException(String.format(((projectCode +"000084: ")+ unableToFindSchema$str()), schemaFile));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String unableToFindSchema$str() {
        return unableToFindSchema;
    }

    @Override
    public final IllegalArgumentException identityTypeFactoryNotImplemented(final String identityType) {
        IllegalArgumentException result = new IllegalArgumentException(String.format(((projectCode +"000002: ")+ identityTypeFactoryNotImplemented$str()), identityType));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String identityTypeFactoryNotImplemented$str() {
        return identityTypeFactoryNotImplemented;
    }

    @Override
    public final String noPolicyContextForIdMessage(final String contextID) {
        String result = String.format(((projectCode +"000092: ")+ noPolicyContextForIdMessage$str()), contextID);
        return result;
    }

    protected String noPolicyContextForIdMessage$str() {
        return noPolicyContextForIdMessage;
    }

    @Override
    public final String pbeUtilsMessage() {
        String result = String.format(((projectCode +"000105: ")+ pbeUtilsMessage$str()));
        return result;
    }

    protected String pbeUtilsMessage$str() {
        return pbeUtilsMessage;
    }

    @Override
    public final IOException failedToFindResource(final String resourceName) {
        IOException result = new IOException(String.format(((projectCode +"000043: ")+ failedToFindResource$str()), resourceName));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String failedToFindResource$str() {
        return failedToFindResource;
    }

    @Override
    public final NamingException unableToFollowReferralForAuth(final String name) {
        NamingException result = new NamingException(String.format(((projectCode +"000038: ")+ unableToFollowReferralForAuth$str()), name));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String unableToFollowReferralForAuth$str() {
        return unableToFollowReferralForAuth;
    }

    @Override
    public final String enterUsernameMessage() {
        String result = String.format(((projectCode +"000029: ")+ enterUsernameMessage$str()));
        return result;
    }

    protected String enterUsernameMessage$str() {
        return enterUsernameMessage;
    }

    @Override
    public final XMLStreamException missingRequiredAttributes(final String attributes, final Location location) {
        XMLStreamException result = new XMLStreamException(String.format(((projectCode +"000085: ")+ missingRequiredAttributes$str()), attributes), location);
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String missingRequiredAttributes$str() {
        return missingRequiredAttributes;
    }

    @Override
    public final IllegalArgumentException missingSystemProperty(final String sysProperty) {
        IllegalArgumentException result = new IllegalArgumentException(String.format(((projectCode +"000132: ")+ missingSystemProperty$str()), sysProperty));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String missingSystemProperty$str() {
        return missingSystemProperty;
    }

    @Override
    public final IllegalArgumentException failedToDecodeBindCredential(final Throwable throwable) {
        IllegalArgumentException result = new IllegalArgumentException(String.format(((projectCode +"000066: ")+ failedToDecodeBindCredential$str())), throwable);
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String failedToDecodeBindCredential$str() {
        return failedToDecodeBindCredential;
    }

    @Override
    public final IOException unableToLoadPropertiesFile(final String fileName) {
        IOException result = new IOException(String.format(((projectCode +"000073: ")+ unableToLoadPropertiesFile$str()), fileName));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String unableToLoadPropertiesFile$str() {
        return unableToLoadPropertiesFile;
    }

    @Override
    public final ProviderException failedToObtainSHAMessageDigest(final Throwable throwable) {
        ProviderException result = new ProviderException(String.format(((projectCode +"000025: ")+ failedToObtainSHAMessageDigest$str())), throwable);
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String failedToObtainSHAMessageDigest$str() {
        return failedToObtainSHAMessageDigest;
    }

    @Override
    public final String failedToResolveTargetStateMessage(final String targetName, final String transitionName) {
        String result = String.format(((projectCode +"000106: ")+ failedToResolveTargetStateMessage$str()), targetName, transitionName);
        return result;
    }

    protected String failedToResolveTargetStateMessage$str() {
        return failedToResolveTargetStateMessage;
    }

    @Override
    public final String unableToCreateVaultMessage() {
        String result = String.format(((projectCode +"000007: ")+ unableToCreateVaultMessage$str()));
        return result;
    }

    protected String unableToCreateVaultMessage$str() {
        return unableToCreateVaultMessage;
    }

    @Override
    public final IllegalStateException missingDelegateForLayer(final String layer) {
        IllegalStateException result = new IllegalStateException(String.format(((projectCode +"000078: ")+ missingDelegateForLayer$str()), layer));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String missingDelegateForLayer$str() {
        return missingDelegateForLayer;
    }

    @Override
    public final String invalidKeystorePasswordFormatMessage() {
        String result = String.format(((projectCode +"000142: ")+ invalidKeystorePasswordFormatMessage$str()));
        return result;
    }

    protected String invalidKeystorePasswordFormatMessage$str() {
        return invalidKeystorePasswordFormatMessage;
    }

    @Override
    public final IllegalStateException invalidThreadContextClassLoader() {
        IllegalStateException result = new IllegalStateException(String.format(((projectCode +"000011: ")+ invalidThreadContextClassLoader$str())));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String invalidThreadContextClassLoader$str() {
        return invalidThreadContextClassLoader;
    }

    @Override
    public final GeneralSecurityException failedToCreateSealedObject(final Throwable throwable) {
        GeneralSecurityException result = new GeneralSecurityException(String.format(((projectCode +"000028: ")+ failedToCreateSealedObject$str())), throwable);
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String failedToCreateSealedObject$str() {
        return failedToCreateSealedObject;
    }

    @Override
    public final String noMatchForAliasMessage(final String alias, final List existingAliases) {
        String result = String.format(((projectCode +"000058: ")+ noMatchForAliasMessage$str()), alias, existingAliases);
        return result;
    }

    protected String noMatchForAliasMessage$str() {
        return noMatchForAliasMessage;
    }

    @Override
    public final IllegalArgumentException unsupportedQOP(final String qop) {
        IllegalArgumentException result = new IllegalArgumentException(String.format(((projectCode +"000041: ")+ unsupportedQOP$str()), qop));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String unsupportedQOP$str() {
        return unsupportedQOP;
    }

    @Override
    public final RuntimeException invalidSecurityAnnotationConfig() {
        RuntimeException result = new RuntimeException(String.format(((projectCode +"000015: ")+ invalidSecurityAnnotationConfig$str())));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String invalidSecurityAnnotationConfig$str() {
        return invalidSecurityAnnotationConfig;
    }

    @Override
    public final String failedToLookupDataSourceMessage(final String jndiName) {
        String result = String.format(((projectCode +"000064: ")+ failedToLookupDataSourceMessage$str()), jndiName);
        return result;
    }

    protected String failedToLookupDataSourceMessage$str() {
        return failedToLookupDataSourceMessage;
    }

    @Override
    public final IllegalStateException missingXACMLPolicyForContextId(final String contextID) {
        IllegalStateException result = new IllegalStateException(String.format(((projectCode +"000080: ")+ missingXACMLPolicyForContextId$str()), contextID));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String missingXACMLPolicyForContextId$str() {
        return missingXACMLPolicyForContextId;
    }

    @Override
    public final String sharedKeyMismatchMessage(final String vaultBlock, final String attributeName) {
        String result = String.format(((projectCode +"000131: ")+ sharedKeyMismatchMessage$str()), vaultBlock, attributeName);
        return result;
    }

    protected String sharedKeyMismatchMessage$str() {
        return sharedKeyMismatchMessage;
    }

    @Override
    public final String deniedByIdentityTrustMessage() {
        String result = String.format(((projectCode +"000005: ")+ deniedByIdentityTrustMessage$str()));
        return result;
    }

    protected String deniedByIdentityTrustMessage$str() {
        return deniedByIdentityTrustMessage;
    }

    @Override
    public final RuntimeException invalidLoginModuleStackRef(final String stackRef) {
        RuntimeException result = new RuntimeException(String.format(((projectCode +"000083: ")+ invalidLoginModuleStackRef$str()), stackRef));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String invalidLoginModuleStackRef$str() {
        return invalidLoginModuleStackRef;
    }

    @Override
    public final LoginException unableToGetPrincipalOrCredsForAssociation() {
        LoginException result = new LoginException(String.format(((projectCode +"000119: ")+ unableToGetPrincipalOrCredsForAssociation$str())));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String unableToGetPrincipalOrCredsForAssociation$str() {
        return unableToGetPrincipalOrCredsForAssociation;
    }

    @Override
    public final IllegalArgumentException invalidType(final String type) {
        IllegalArgumentException result = new IllegalArgumentException(String.format(((projectCode +"000003: ")+ invalidType$str()), type));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String invalidType$str() {
        return invalidType;
    }

    @Override
    public final IllegalStateException missingServiceAuthToken(final String securityDomain) {
        IllegalStateException result = new IllegalStateException(String.format(((projectCode +"000115: ")+ missingServiceAuthToken$str()), securityDomain));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String missingServiceAuthToken$str() {
        return missingServiceAuthToken;
    }

    @Override
    public final String filePasswordUsageMessage() {
        String result = String.format(((projectCode +"000102: ")+ filePasswordUsageMessage$str()));
        return result;
    }

    protected String filePasswordUsageMessage$str() {
        return filePasswordUsageMessage;
    }

    @Override
    public final String unableToEncryptDataMessage() {
        String result = String.format(((projectCode +"000128: ")+ unableToEncryptDataMessage$str()));
        return result;
    }

    protected String unableToEncryptDataMessage$str() {
        return unableToEncryptDataMessage;
    }

    @Override
    public final String unableToInitializeLoginContext(final Throwable cause) {
        String result = String.format(((projectCode +"000143: ")+ unableToInitializeLoginContext$str()));
        return result;
    }

    protected String unableToInitializeLoginContext$str() {
        return unableToInitializeLoginContext;
    }

    @Override
    public final RuntimeException invalidNullSecurityContext() {
        RuntimeException result = new RuntimeException(String.format(((projectCode +"000035: ")+ invalidNullSecurityContext$str())));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String invalidNullSecurityContext$str() {
        return invalidNullSecurityContext;
    }

    @Override
    public final RuntimeException invalidNullKeyStoreURL(final String keystoreType) {
        RuntimeException result = new RuntimeException(String.format(((projectCode +"000117: ")+ invalidNullKeyStoreURL$str()), keystoreType));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String invalidNullKeyStoreURL$str() {
        return invalidNullKeyStoreURL;
    }

    @Override
    public final RuntimeException noSecretKeyandAliasAlreadyUsed(final String alias) {
        RuntimeException result = new RuntimeException(String.format(((projectCode +"000138: ")+ noSecretKeyandAliasAlreadyUsed$str()), alias));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String noSecretKeyandAliasAlreadyUsed$str() {
        return noSecretKeyandAliasAlreadyUsed;
    }

    @Override
    public final XMLStreamException unexpectedElement(final String elementName, final Location location) {
        XMLStreamException result = new XMLStreamException(String.format(((projectCode +"000086: ")+ unexpectedElement$str()), elementName), location);
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String unexpectedElement$str() {
        return unexpectedElement;
    }

    @Override
    public final RuntimeException invalidPasswordType(final Class type) {
        RuntimeException result = new RuntimeException(String.format(((projectCode +"000039: ")+ invalidPasswordType$str()), type));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String invalidPasswordType$str() {
        return invalidPasswordType;
    }

    @Override
    public final String cacheValidationFailedMessage() {
        String result = String.format(((projectCode +"000082: ")+ cacheValidationFailedMessage$str()));
        return result;
    }

    protected String cacheValidationFailedMessage$str() {
        return cacheValidationFailedMessage;
    }

    @Override
    public final LoginException missingPropertiesFile(final String fileName) {
        LoginException result = new LoginException(String.format(((projectCode +"000059: ")+ missingPropertiesFile$str()), fileName));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String missingPropertiesFile$str() {
        return missingPropertiesFile;
    }

    @Override
    public final String base64EncoderMessage() {
        String result = String.format(((projectCode +"000111: ")+ base64EncoderMessage$str()));
        return result;
    }

    protected String base64EncoderMessage$str() {
        return base64EncoderMessage;
    }

    @Override
    public final IllegalStateException invalidPermissionChecks() {
        IllegalStateException result = new IllegalStateException(String.format(((projectCode +"000077: ")+ invalidPermissionChecks$str())));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String invalidPermissionChecks$str() {
        return invalidPermissionChecks;
    }

    @Override
    public final String unableToFindSetSecurityInfoMessage() {
        String result = String.format(((projectCode +"000010: ")+ unableToFindSetSecurityInfoMessage$str()));
        return result;
    }

    protected String unableToFindSetSecurityInfoMessage$str() {
        return unableToFindSetSecurityInfoMessage;
    }

    @Override
    public final IllegalArgumentException invalidEJBVersion(final String version) {
        IllegalArgumentException result = new IllegalArgumentException(String.format(((projectCode +"000099: ")+ invalidEJBVersion$str()), version));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String invalidEJBVersion$str() {
        return invalidEJBVersion;
    }

    @Override
    public final String sizeMismatchMessage(final String param1, final String param2) {
        String result = String.format(((projectCode +"000042: ")+ sizeMismatchMessage$str()), param1, param2);
        return result;
    }

    protected String sizeMismatchMessage$str() {
        return sizeMismatchMessage;
    }

    @Override
    public final LoginException missingXMLUserRolesMapping() {
        LoginException result = new LoginException(String.format(((projectCode +"000074: ")+ missingXMLUserRolesMapping$str())));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String missingXMLUserRolesMapping$str() {
        return missingXMLUserRolesMapping;
    }

    @Override
    public final IllegalStateException failedToObtainAuthorizationInfo(final String securityDomain) {
        IllegalStateException result = new IllegalStateException(String.format(((projectCode +"000096: ")+ failedToObtainAuthorizationInfo$str()), securityDomain));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String failedToObtainAuthorizationInfo$str() {
        return failedToObtainAuthorizationInfo;
    }

    @Override
    public final SecurityException failedToObtainUsername(final Throwable throwable) {
        SecurityException result = new SecurityException(String.format(((projectCode +"000031: ")+ failedToObtainUsername$str())), throwable);
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String failedToObtainUsername$str() {
        return failedToObtainUsername;
    }

    @Override
    public final FailedLoginException failedToMatchCredential(final String alias) {
        FailedLoginException result = new FailedLoginException(String.format(((projectCode +"000052: ")+ failedToMatchCredential$str()), alias));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String failedToMatchCredential$str() {
        return failedToMatchCredential;
    }

    @Override
    public final IllegalArgumentException invalidVaultStringFormat(final String vaultString) {
        IllegalArgumentException result = new IllegalArgumentException(String.format(((projectCode +"000009: ")+ invalidVaultStringFormat$str()), vaultString));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String invalidVaultStringFormat$str() {
        return invalidVaultStringFormat;
    }

    @Override
    public final IllegalStateException invalidNullAuthConfigProviderForLayer(final String layer, final String contextID) {
        IllegalStateException result = new IllegalStateException(String.format(((projectCode +"000095: ")+ invalidNullAuthConfigProviderForLayer$str()), layer, contextID));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String invalidNullAuthConfigProviderForLayer$str() {
        return invalidNullAuthConfigProviderForLayer;
    }

    @Override
    public final RuntimeException noMatchingRoleFoundInDescriptor(final String roleName) {
        RuntimeException result = new RuntimeException(String.format(((projectCode +"000076: ")+ noMatchingRoleFoundInDescriptor$str()), roleName));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String noMatchingRoleFoundInDescriptor$str() {
        return noMatchingRoleFoundInDescriptor;
    }

    @Override
    public final String cacheMissMessage() {
        String result = String.format(((projectCode +"000081: ")+ cacheMissMessage$str()));
        return result;
    }

    protected String cacheMissMessage$str() {
        return cacheMissMessage;
    }

    @Override
    public final RuntimeException unableToCreateACLPersistenceStrategy(final Throwable throwable) {
        RuntimeException result = new RuntimeException(String.format(((projectCode +"000021: ")+ unableToCreateACLPersistenceStrategy$str())), throwable);
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String unableToCreateACLPersistenceStrategy$str() {
        return unableToCreateACLPersistenceStrategy;
    }

    @Override
    public final RuntimeException unrecognizedVaultContentVersion(final String readVersion, final String fromVersion, final String toVersion) {
        RuntimeException result = new RuntimeException(String.format(((projectCode +"000134: ")+ unrecognizedVaultContentVersion$str()), readVersion, fromVersion, toVersion));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String unrecognizedVaultContentVersion$str() {
        return unrecognizedVaultContentVersion;
    }

    @Override
    public final String failedToRetrieveCertificateMessage(final String publicKeyAlias) {
        String result = String.format(((projectCode +"000126: ")+ failedToRetrieveCertificateMessage$str()), publicKeyAlias);
        return result;
    }

    protected String failedToRetrieveCertificateMessage$str() {
        return failedToRetrieveCertificateMessage;
    }

    @Override
    public final RuntimeException unableToInitSecurityFactory(final Throwable throwable) {
        RuntimeException result = new RuntimeException(String.format(((projectCode +"000013: ")+ unableToInitSecurityFactory$str())), throwable);
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String unableToInitSecurityFactory$str() {
        return unableToInitSecurityFactory;
    }

    @Override
    public final FailedLoginException invalidPassword() {
        FailedLoginException result = new FailedLoginException(String.format(((projectCode +"000070: ")+ invalidPassword$str())));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String invalidPassword$str() {
        return invalidPassword;
    }

    @Override
    public final String unableToWriteShareKeyFileMessage() {
        String result = String.format(((projectCode +"000129: ")+ unableToWriteShareKeyFileMessage$str()));
        return result;
    }

    protected String unableToWriteShareKeyFileMessage$str() {
        return unableToWriteShareKeyFileMessage;
    }

    @Override
    public final LoginException unableToGetCertificateFromClass(final Class certClass) {
        LoginException result = new LoginException(String.format(((projectCode +"000054: ")+ unableToGetCertificateFromClass$str()), certClass));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String unableToGetCertificateFromClass$str() {
        return unableToGetCertificateFromClass;
    }

    @Override
    public final String existingCredentialMessage() {
        String result = String.format(((projectCode +"000057: ")+ existingCredentialMessage$str()));
        return result;
    }

    protected String existingCredentialMessage$str() {
        return existingCredentialMessage;
    }

    @Override
    public final String unableToLoadVaultMessage() {
        String result = String.format(((projectCode +"000006: ")+ unableToLoadVaultMessage$str()));
        return result;
    }

    protected String unableToLoadVaultMessage$str() {
        return unableToLoadVaultMessage;
    }

    @Override
    public final String failedToProcessQueryMessage() {
        String result = String.format(((projectCode +"000065: ")+ failedToProcessQueryMessage$str()));
        return result;
    }

    protected String failedToProcessQueryMessage$str() {
        return failedToProcessQueryMessage;
    }

    @Override
    public final NumberFormatException illegalBase64Character() {
        NumberFormatException result = new NumberFormatException(String.format(((projectCode +"000113: ")+ illegalBase64Character$str())));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String illegalBase64Character$str() {
        return illegalBase64Character;
    }

    @Override
    public final IOException unableToFindPropertiesFile(final String fileName) {
        IOException result = new IOException(String.format(((projectCode +"000072: ")+ unableToFindPropertiesFile$str()), fileName));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String unableToFindPropertiesFile$str() {
        return unableToFindPropertiesFile;
    }

    @Override
    public final String identityTrustValidationFailedMessage() {
        String result = String.format(((projectCode +"000089: ")+ identityTrustValidationFailedMessage$str()));
        return result;
    }

    protected String identityTrustValidationFailedMessage$str() {
        return identityTrustValidationFailedMessage;
    }

    @Override
    public final RuntimeException vaultDoesnotContainSecretKey(final String alias) {
        RuntimeException result = new RuntimeException(String.format(((projectCode +"000137: ")+ vaultDoesnotContainSecretKey$str()), alias));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String vaultDoesnotContainSecretKey$str() {
        return vaultDoesnotContainSecretKey;
    }

    @Override
    public final FailedLoginException noMatchingUsernameFoundInPrincipals() {
        FailedLoginException result = new FailedLoginException(String.format(((projectCode +"000062: ")+ noMatchingUsernameFoundInPrincipals$str())));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String noMatchingUsernameFoundInPrincipals$str() {
        return noMatchingUsernameFoundInPrincipals;
    }

    @Override
    public final LoginException noCallbackHandlerAvailable() {
        LoginException result = new LoginException(String.format(((projectCode +"000053: ")+ noCallbackHandlerAvailable$str())));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String noCallbackHandlerAvailable$str() {
        return noCallbackHandlerAvailable;
    }

    @Override
    public final RuntimeException missingAdminKeyInOriginalVaultData() {
        RuntimeException result = new RuntimeException(String.format(((projectCode +"000136: ")+ missingAdminKeyInOriginalVaultData$str())));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String missingAdminKeyInOriginalVaultData$str() {
        return missingAdminKeyInOriginalVaultData;
    }

    @Override
    public final String missingRequiredModuleOptionMessage(final String moduleOption) {
        String result = String.format(((projectCode +"000067: ")+ missingRequiredModuleOptionMessage$str()), moduleOption);
        return result;
    }

    protected String missingRequiredModuleOptionMessage$str() {
        return missingRequiredModuleOptionMessage;
    }

    @Override
    public final IllegalStateException noServerAuthModuleForRequestType(final Class requestType) {
        IllegalStateException result = new IllegalStateException(String.format(((projectCode +"000050: ")+ noServerAuthModuleForRequestType$str()), requestType));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String noServerAuthModuleForRequestType$str() {
        return noServerAuthModuleForRequestType;
    }

    @Override
    public final IllegalStateException failedToObtainApplicationPolicy(final String securityDomain) {
        IllegalStateException result = new IllegalStateException(String.format(((projectCode +"000048: ")+ failedToObtainApplicationPolicy$str()), securityDomain));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String failedToObtainApplicationPolicy$str() {
        return failedToObtainApplicationPolicy;
    }

    @Override
    public final String invalidUnmaskedKeystorePasswordMessage() {
        String result = String.format(((projectCode +"000122: ")+ invalidUnmaskedKeystorePasswordMessage$str()));
        return result;
    }

    protected String invalidUnmaskedKeystorePasswordMessage$str() {
        return invalidUnmaskedKeystorePasswordMessage;
    }

    @Override
    public final IllegalStateException unableToLocateMBeanServer() {
        IllegalStateException result = new IllegalStateException(String.format(((projectCode +"000108: ")+ unableToLocateMBeanServer$str())));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String unableToLocateMBeanServer$str() {
        return unableToLocateMBeanServer;
    }

    @Override
    public final String fileOrDirectoryDoesNotExistMessage(final String fileName) {
        String result = String.format(((projectCode +"000123: ")+ fileOrDirectoryDoesNotExistMessage$str()), fileName);
        return result;
    }

    protected String fileOrDirectoryDoesNotExistMessage$str() {
        return fileOrDirectoryDoesNotExistMessage;
    }

    @Override
    public final IllegalArgumentException invalidControlFlag(final String flag) {
        IllegalArgumentException result = new IllegalArgumentException(String.format(((projectCode +"000001: ")+ invalidControlFlag$str()), flag));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String invalidControlFlag$str() {
        return invalidControlFlag;
    }

    @Override
    public final RuntimeException invalidPolicyRegistrationType(final String type) {
        RuntimeException result = new RuntimeException(String.format(((projectCode +"000104: ")+ invalidPolicyRegistrationType$str()), type));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String invalidPolicyRegistrationType$str() {
        return invalidPolicyRegistrationType;
    }

    @Override
    public final String nullRolesInSubjectMessage() {
        String result = String.format(((projectCode +"000018: ")+ nullRolesInSubjectMessage$str()));
        return result;
    }

    protected String nullRolesInSubjectMessage$str() {
        return nullRolesInSubjectMessage;
    }

    @Override
    public final LoginException unableToGetPasswordFromVault() {
        LoginException result = new LoginException(String.format(((projectCode +"000069: ")+ unableToGetPasswordFromVault$str())));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String unableToGetPasswordFromVault$str() {
        return unableToGetPasswordFromVault;
    }

    @Override
    public final RuntimeException unableToGetKeyStore(final Throwable throwable, final String file) {
        RuntimeException result = new RuntimeException(String.format(((projectCode +"000140: ")+ unableToGetKeyStore$str()), file), throwable);
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String unableToGetKeyStore$str() {
        return unableToGetKeyStore;
    }

    @Override
    public final SecurityException failedToRegisterAuthConfigProvider(final String providerClass, final Throwable throwable) {
        SecurityException result = new SecurityException(String.format(((projectCode +"000045: ")+ failedToRegisterAuthConfigProvider$str()), providerClass), throwable);
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String failedToRegisterAuthConfigProvider$str() {
        return failedToRegisterAuthConfigProvider;
    }

    @Override
    public final IllegalStateException invalidNullTransactionManager() {
        IllegalStateException result = new IllegalStateException(String.format(((projectCode +"000061: ")+ invalidNullTransactionManager$str())));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String invalidNullTransactionManager$str() {
        return invalidNullTransactionManager;
    }

    @Override
    public final IllegalStateException callbackHandlerSysPropertyNotSet(final String systemPropertyName) {
        IllegalStateException result = new IllegalStateException(String.format(((projectCode +"000046: ")+ callbackHandlerSysPropertyNotSet$str()), systemPropertyName));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String callbackHandlerSysPropertyNotSet$str() {
        return callbackHandlerSysPropertyNotSet;
    }

    @Override
    public final RuntimeException unableToLookupDataSource() {
        RuntimeException result = new RuntimeException(String.format(((projectCode +"000034: ")+ unableToLookupDataSource$str())));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String unableToLookupDataSource$str() {
        return unableToLookupDataSource;
    }

    @Override
    public final String authenticationFailedMessage() {
        String result = String.format(((projectCode +"000016: ")+ authenticationFailedMessage$str()));
        return result;
    }

    protected String authenticationFailedMessage$str() {
        return authenticationFailedMessage;
    }

    @Override
    public final RuntimeException failedToCreateDocumentBuilder(final Throwable throwable) {
        RuntimeException result = new RuntimeException(String.format(((projectCode +"000109: ")+ failedToCreateDocumentBuilder$str())), throwable);
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String failedToCreateDocumentBuilder$str() {
        return failedToCreateDocumentBuilder;
    }

    @Override
    public final LoginException failedToInvokeCallbackHandler() {
        LoginException result = new LoginException(String.format(((projectCode +"000055: ")+ failedToInvokeCallbackHandler$str())));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String failedToInvokeCallbackHandler$str() {
        return failedToInvokeCallbackHandler;
    }

    @Override
    public final IllegalArgumentException unsupportedAlgorithm(final String algorithm) {
        IllegalArgumentException result = new IllegalArgumentException(String.format(((projectCode +"000040: ")+ unsupportedAlgorithm$str()), algorithm));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String unsupportedAlgorithm$str() {
        return unsupportedAlgorithm;
    }

    @Override
    public final IllegalStateException aclEntryPermissionAlreadySet() {
        IllegalStateException result = new IllegalStateException(String.format(((projectCode +"000019: ")+ aclEntryPermissionAlreadySet$str())));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String aclEntryPermissionAlreadySet$str() {
        return aclEntryPermissionAlreadySet;
    }

    @Override
    public final FailedLoginException noMatchingUsernameFoundInRoles() {
        FailedLoginException result = new FailedLoginException(String.format(((projectCode +"000063: ")+ noMatchingUsernameFoundInRoles$str())));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String noMatchingUsernameFoundInRoles$str() {
        return noMatchingUsernameFoundInRoles;
    }

    @Override
    public final String failedToRetrievePublicKeyMessage(final String publicKeyAlias) {
        String result = String.format(((projectCode +"000125: ")+ failedToRetrievePublicKeyMessage$str()), publicKeyAlias);
        return result;
    }

    protected String failedToRetrievePublicKeyMessage$str() {
        return failedToRetrievePublicKeyMessage;
    }

    @Override
    public final IllegalStateException invalidNullProperty(final String property) {
        IllegalStateException result = new IllegalStateException(String.format(((projectCode +"000075: ")+ invalidNullProperty$str()), property));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String invalidNullProperty$str() {
        return invalidNullProperty;
    }

    @Override
    public final String unableToLocateACLForResourceMessage(final String resource) {
        String result = String.format(((projectCode +"000022: ")+ unableToLocateACLForResourceMessage$str()), resource);
        return result;
    }

    protected String unableToLocateACLForResourceMessage$str() {
        return unableToLocateACLForResourceMessage;
    }

    @Override
    public final String invalidNullOrEmptyOptionMessage(final String optionName) {
        String result = String.format(((projectCode +"000121: ")+ invalidNullOrEmptyOptionMessage$str()), optionName);
        return result;
    }

    protected String invalidNullOrEmptyOptionMessage$str() {
        return invalidNullOrEmptyOptionMessage;
    }

    @Override
    public final String invalidTransitionForActionMessage(final String actionName, final String stateName) {
        String result = String.format(((projectCode +"000107: ")+ invalidTransitionForActionMessage$str()), actionName, stateName);
        return result;
    }

    protected String invalidTransitionForActionMessage$str() {
        return invalidTransitionForActionMessage;
    }

    @Override
    public final IllegalArgumentException malformedIdentityString(final String identityString) {
        IllegalArgumentException result = new IllegalArgumentException(String.format(((projectCode +"000024: ")+ malformedIdentityString$str()), identityString));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String malformedIdentityString$str() {
        return malformedIdentityString;
    }

    @Override
    public final SecurityException failedToVerifyServiceAuthToken() {
        SecurityException result = new SecurityException(String.format(((projectCode +"000116: ")+ failedToVerifyServiceAuthToken$str())));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String failedToVerifyServiceAuthToken$str() {
        return failedToVerifyServiceAuthToken;
    }

    @Override
    public final IllegalStateException invalidNullLoginConfig() {
        IllegalStateException result = new IllegalStateException(String.format(((projectCode +"000012: ")+ invalidNullLoginConfig$str())));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String invalidNullLoginConfig$str() {
        return invalidNullLoginConfig;
    }

    @Override
    public final String authorizationFailedMessage() {
        String result = String.format(((projectCode +"000017: ")+ authorizationFailedMessage$str()));
        return result;
    }

    protected String authorizationFailedMessage$str() {
        return authorizationFailedMessage;
    }

    @Override
    public final String moduleAbortFailedMessage() {
        String result = String.format(((projectCode +"000091: ")+ moduleAbortFailedMessage$str()));
        return result;
    }

    protected String moduleAbortFailedMessage$str() {
        return moduleAbortFailedMessage;
    }

    @Override
    public final String invalidSharedKeyMessage() {
        String result = String.format(((projectCode +"000127: ")+ invalidSharedKeyMessage$str()));
        return result;
    }

    protected String invalidSharedKeyMessage$str() {
        return invalidSharedKeyMessage;
    }

    @Override
    public final String invalidDirectoryFormatMessage(final String directory) {
        String result = String.format(((projectCode +"000124: ")+ invalidDirectoryFormatMessage$str()), directory);
        return result;
    }

    protected String invalidDirectoryFormatMessage$str() {
        return invalidDirectoryFormatMessage;
    }

    @Override
    public final IllegalArgumentException invalidPasswordCommandType(final String type) {
        IllegalArgumentException result = new IllegalArgumentException(String.format(((projectCode +"000118: ")+ invalidPasswordCommandType$str()), type));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String invalidPasswordCommandType$str() {
        return invalidPasswordCommandType;
    }

    @Override
    public final RuntimeException failedToMatchStrings(final String one, final String two) {
        RuntimeException result = new RuntimeException(String.format(((projectCode +"000133: ")+ failedToMatchStrings$str()), one, two));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String failedToMatchStrings$str() {
        return failedToMatchStrings;
    }

    @Override
    public final IllegalStateException aclResourceAlreadySet() {
        IllegalStateException result = new IllegalStateException(String.format(((projectCode +"000020: ")+ aclResourceAlreadySet$str())));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String aclResourceAlreadySet$str() {
        return aclResourceAlreadySet;
    }

    @Override
    public final RuntimeException failedToFindNamespaceURI(final String elementName) {
        RuntimeException result = new RuntimeException(String.format(((projectCode +"000110: ")+ failedToFindNamespaceURI$str()), elementName));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String failedToFindNamespaceURI$str() {
        return failedToFindNamespaceURI;
    }

    @Override
    public final IllegalArgumentException invalidNullArgument(final String argumentName) {
        IllegalArgumentException result = new IllegalArgumentException(String.format(((projectCode +"000004: ")+ invalidNullArgument$str()), argumentName));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String invalidNullArgument$str() {
        return invalidNullArgument;
    }

    @Override
    public final String moduleCommitFailedMessage() {
        String result = String.format(((projectCode +"000090: ")+ moduleCommitFailedMessage$str()));
        return result;
    }

    protected String moduleCommitFailedMessage$str() {
        return moduleCommitFailedMessage;
    }

    @Override
    public final RuntimeException mixedVaultDataFound(final String vaultDatFile, final String encDatFile) {
        RuntimeException result = new RuntimeException(String.format(((projectCode +"000135: ")+ mixedVaultDataFound$str()), vaultDatFile, encDatFile));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String mixedVaultDataFound$str() {
        return mixedVaultDataFound;
    }

    @Override
    public final String enterPasswordMessage() {
        String result = String.format(((projectCode +"000030: ")+ enterPasswordMessage$str()));
        return result;
    }

    protected String enterPasswordMessage$str() {
        return enterPasswordMessage;
    }

    @Override
    public final String suppliedCredentialMessage() {
        String result = String.format(((projectCode +"000056: ")+ suppliedCredentialMessage$str()));
        return result;
    }

    protected String suppliedCredentialMessage$str() {
        return suppliedCredentialMessage;
    }

    @Override
    public final KeyException failedToCreateSecretKeySpec(final Throwable throwable) {
        KeyException result = new KeyException(String.format(((projectCode +"000026: ")+ failedToCreateSecretKeySpec$str())), throwable);
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String failedToCreateSecretKeySpec$str() {
        return failedToCreateSecretKeySpec;
    }

    @Override
    public final String unableToLocateACLWithNoStrategyMessage() {
        String result = String.format(((projectCode +"000023: ")+ unableToLocateACLWithNoStrategyMessage$str()));
        return result;
    }

    protected String unableToLocateACLWithNoStrategyMessage$str() {
        return unableToLocateACLWithNoStrategyMessage;
    }

    @Override
    public final NamingException failedToFindBaseContextDN(final String baseDN) {
        NamingException result = new NamingException(String.format(((projectCode +"000037: ")+ failedToFindBaseContextDN$str()), baseDN));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String failedToFindBaseContextDN$str() {
        return failedToFindBaseContextDN;
    }

    @Override
    public final UnsupportedCallbackException unableToHandleCallback(final Callback callback, final String callbackHandler, final String callbackType) {
        UnsupportedCallbackException result = new UnsupportedCallbackException(callback);
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String unableToHandleCallback$str() {
        return unableToHandleCallback;
    }

    @Override
    public final AttributeNotFoundException invalidMBeanAttribute(final String attrName) {
        AttributeNotFoundException result = new AttributeNotFoundException(String.format(((projectCode +"000101: ")+ invalidMBeanAttribute$str()), attrName));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String invalidMBeanAttribute$str() {
        return invalidMBeanAttribute;
    }

    @Override
    public final XMLStreamException unexpectedAttribute(final String attributeName, final Location location) {
        XMLStreamException result = new XMLStreamException(String.format(((projectCode +"000087: ")+ unexpectedAttribute$str()), attributeName), location);
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String unexpectedAttribute$str() {
        return unexpectedAttribute;
    }

    @Override
    public final RuntimeException unableToFindPrincipalInDB(final String principalName) {
        RuntimeException result = new RuntimeException(String.format(((projectCode +"000033: ")+ unableToFindPrincipalInDB$str()), principalName));
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String unableToFindPrincipalInDB$str() {
        return unableToFindPrincipalInDB;
    }

    @Override
    public final String operationNotAllowedMessage() {
        String result = String.format(((projectCode +"000093: ")+ operationNotAllowedMessage$str()));
        return result;
    }

    protected String operationNotAllowedMessage$str() {
        return operationNotAllowedMessage;
    }

    @Override
    public final KeyException unexpectedExceptionDuringSecretKeyCreation(final Throwable throwable) {
        KeyException result = new KeyException(String.format(((projectCode +"000027: ")+ unexpectedExceptionDuringSecretKeyCreation$str())), throwable);
        StackTraceElement[] st = result.getStackTrace();
        result.setStackTrace(Arrays.copyOfRange(st, 1, st.length));
        return result;
    }

    protected String unexpectedExceptionDuringSecretKeyCreation$str() {
        return unexpectedExceptionDuringSecretKeyCreation;
    }

}
