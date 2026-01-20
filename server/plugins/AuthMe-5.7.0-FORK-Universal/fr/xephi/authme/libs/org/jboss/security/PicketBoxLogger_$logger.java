
package org.jboss.security;

import java.io.Serializable;
import java.net.URL;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import javax.annotation.Generated;
import javax.security.auth.Subject;
import org.jboss.logging.BasicLogger;
import org.jboss.logging.DelegatingBasicLogger;
import org.jboss.logging.Logger;


/**
 * Warning this class consists of generated code.
 * 
 */
@Generated(value = "org.jboss.logging.processor.model.MessageLoggerImplementor", date = "2014-11-11T23:27:00-0200")
public class PicketBoxLogger_$logger
    extends DelegatingBasicLogger
    implements Serializable, BasicLogger, PicketBoxLogger
{

    private final static long serialVersionUID = 1L;
    private final static String projectCode = "PBOX";
    private final static String FQCN = PicketBoxLogger_$logger.class.getName();
    private final static String traceEndDoesUserHaveRole = "End doesUserHaveRole, result: %s";
    private final static String debugFailureToQueryLDAPAttribute = "Failed to query %s from %s";
    private final static String traceBeginIsValid = "Begin isValid, principal: %s, cache entry: %s";
    private final static String debugAuthorizationError = "Authorization processing error";
    private final static String traceRemoveAppConfig = "removeAppConfig(%s)";
    private final static String traceInsertedCacheInfo = "Inserted cache info: %s";
    private final static String traceCertificateFound = "Found certificate, serial number: %s, subject DN: %s";
    private final static String traceObtainedAuthInfoFromHandler = "Obtained auth info from handler, principal: %s, credential class: %s";
    private final static String vaultDoesnotContainSecretKey = "Security Vault does not contain SecretKey entry under alias (%s)";
    private final static String debugFailureToFindAttrInSearchResult = "No attribute %s found in search result %s";
    private final static String traceHasUserDataPermission = "hasUserDataPermission, permission: %s, allowed: %s";
    private final static String debugErrorGettingRequestFromPolicyContext = "Error getting request from policy context";
    private final static String debugLoadConfigAsXML = "Try loading config as XML from %s";
    private final static String traceAddPermissionToUncheckedPolicy = "addToUncheckedPolicy, permission: %s";
    private final static String debugBadPasswordForUsername = "Bad password for username %s";
    private final static String traceMappedX500Principal = "Mapped X500 principal, new principal: %s";
    private final static String traceBeginCommit = "Begin commit method, overall result: %s";
    private final static String debugJBossPolicyConfigurationConstruction = "Constructing JBossPolicyConfiguration with contextID %s";
    private final static String debugFailureToExecuteRolesDNSearch = "Failed to locate roles";
    private final static String unsupportedHashEncodingFormat = "Unsupported hash encoding format: %s";
    private final static String wrongBase64StringUsed = "Wrong Base64 string used with masked password utility. Following is correct (%s)";
    private final static String errorGettingModuleInformation = "Error getting the module classloader informations for cache";
    private final static String traceSecRolesAssociationSetSecurityRoles = "Setting security roles ThreadLocal: %s";
    private final static String debugFailureToLoadPropertiesFile = "Failed to load properties file %s";
    private final static String traceDefaultLoginPrincipal = "defaultLogin, principal: %s";
    private final static String debugIgnoredException = "Exception caught";
    private final static String errorCannotGetMD5AlgorithmInstance = "Cannot get MD5 algorithm instance for hashing password commands. Using NULL.";
    private final static String traceDeregisterPolicy = "Deregistered policy for contextID: %s, type: %s";
    private final static String traceCurrentCallingPrincipal = "Current calling principal: %s, thread name: %s";
    private final static String traceAddPermissionToRole = "addToRole, permission: %s";
    private final static String traceBeginResolvePublicID = "Begin resolvePublicId, publicId: %s";
    private final static String traceMappedSystemIdToFilename = "Mapped systemId to filename %s";
    private final static String traceResettingCache = "Resetting cache";
    private final static String traceBeginGetIdentity = "Begin getIdentity, username: %s";
    private final static String traceFollowRoleDN = "Following roleDN %s";
    private final static String traceBeginGetAppConfigEntry = "Begin getAppConfigurationEntry(%s), size: %s";
    private final static String tracePolicyConfigurationCommit = "commit, contextID: %s";
    private final static String debugImpliesParameters = "Checking role: %s, permissions: %s";
    private final static String debugInvalidWebJaccCheck = "Check is not resourcePerm, userDataPerm or roleRefPerm";
    private final static String traceStoringPasswordToCache = "Storing password to the cache for key: %s";
    private final static String debugInsufficientMethodPermissions = "Insufficient method permissions [principal: %s, EJB name: %s, method: %s, interface: %s, required roles: %s, principal roles: %s, run-as roles: %s]";
    private final static String ambiguosKeyForSecurityVaultTransformation = "Ambiguos vault block and attribute name stored in original security vault. Delimiter (%s) is part of vault block or attribute name. Took the first delimiter. Result vault block (%s) attribute name (%s). Modify security vault manually.";
    private final static String traceExecuteQuery = "Executing query %s with username %s";
    private final static String debugFailedLogin = "Login failure";
    private final static String cannotDeleteOriginalVaultFile = "Cannot delete original security vault file (%s). Delete the file manually before next start, please.";
    private final static String errorGettingJSSESecurityDomain = "The JSSE security domain %s is not valid. All authentication using this login module will fail!";
    private final static String traceEndGetAliasAndCert = "End getAliasAndCert method";
    private final static String traceHostThreadLocalSet = "Setting host %s on thread [id: %s]";
    private final static String errorDecryptingBindCredential = "Exception while decrypting bindCredential";
    private final static String debugLoadConfigAsSun = "Failed to load config as XML. Try loading as Sun format from %s";
    private final static String traceUpdateCache = "updateCache, input subject: %s, cached subject: %s";
    private final static String errorParsingTimeoutNumber = "Error parsing time out number.";
    private final static String warnResolvingSystemIdAsNonFileURL = "Trying to resolve systemId %s as a non-file URL";
    private final static String traceAddPermissionsToExcludedPolicy = "addToExcludedPolicy, permission collection: %s";
    private final static String traceBeginDoesUserHaveRole = "Begin doesUserHaveRole, principal: %s, roles: %s";
    private final static String traceImpliesMatchesExcludedSet = "Denied: matched excluded set, permission %s";
    private final static String traceNoMethodPermissions = "No method permissions assigned to method: %s, interface: %s";
    private final static String debugFailureExecutingMethod = "%s processing failed";
    private final static String traceNoPrincipalsInProtectionDomain = "Not principals found in protection domain %s";
    private final static String traceStateMachineNextState = "nextState for action %s: %s";
    private final static String tracePolicyConfigurationDelete = "delete, contextID: %s";
    private final static String traceRemoveRole = "removeRole, role name: %s, contextID: %s";
    private final static String debugPasswordHashing = "Password hashing activated, algorithm: %s, encoding: %s, charset: %s, callback: %s, storeCallBack: %s";
    private final static String debugEJBPolicyModuleDelegateState = "Method: %s, interface: %s, required roles: %s";
    private final static String traceBeginValidateCredential = "Begin validateCredential method";
    private final static String traceNoPolicyContextForId = "No PolicyContext found for contextID %s";
    private final static String traceEndGetAppConfigEntryWithSuccess = "End getAppConfigurationEntry(%s), AuthInfo: %s";
    private final static String traceQueryWithEmptyResult = "Query returned an empty result";
    private final static String traceCacheEntryLogoutFailure = "Cache entry logout failed";
    private final static String debugFailureToOpenPropertiesFromURL = "Failed to open properties file from URL";
    private final static String warnNullCredentialFromCallbackHandler = "CallbackHandler did not provide a credential";
    private final static String traceBeginResolveSystemIDasURL = "Begin resolveSystemIdasURL, systemId: %s";
    private final static String traceRemoveUncheckedPolicy = "removeUncheckedPolicy, contextID: %s";
    private final static String traceEndLogin = "End login method, isValid: %s";
    private final static String traceEndLoadConfigWithSuccess = "End loadConfig, loginConfigURL: %s";
    private final static String traceFlushCacheEntry = "Flushing %s from security cache";
    private final static String traceBindingLDAPUsername = "Binding username %s";
    private final static String traceLogoutSubject = "JAAS logout, login context: %s, subject: %s";
    private final static String errorFindingCharset = "Charset %s not found. Using platform default";
    private final static String debugJACCDeniedAccess = "JACC delegate access denied [permission: %s, caller: %s, roles: %s";
    private final static String traceEndValidteCache = "End validateCache, result = %s";
    private final static String traceCheckSearchResult = "Checking search result %s";
    private final static String traceAssignUserToRole = "Assigning user to role %s";
    private final static String traceEndExecPasswordCmd = "End execPasswordCmd, exit code: %s";
    private final static String traceBeginExecPasswordCmd = "Begin execPasswordCmd, command: %s";
    private final static String traceMappedResourceToURL = "Mapped resource %s to URL %s";
    private final static String traceIgnoreXMLAttribute = "Ignore attribute [uri: %s, qname: %s, value: %s]";
    private final static String traceBeginGetAliasAndCert = "Begin getAliasAndCert method";
    private final static String traceRebindWithConfiguredPrincipal = "Rebind security principal to %s";
    private final static String warnFailureToValidateCertificate = "Failed to validate certificate: SecurityDomain, Keystore or certificate is null";
    private final static String debugNullAuthorizationManager = "AuthorizationManager is null for security domain %s";
    private final static String traceSystemIDMismatch = "systemId argument '%s' for publicId '%s' is different from the registered systemId '%s', resolution will be based on the argument";
    private final static String traceAddPermissionsToRole = "addToRole, permission collection: %s";
    private final static String traceBeginAbort = "Begin abort method";
    private final static String traceRetrievingPasswordFromCache = "Retrieving password from the cache for key: %s";
    private final static String traceValidatingUsingVerifier = "Validating certificate using verifier %s";
    private final static String traceDBCertLoginModuleOptions = "Module options [dsJndiName: %s, principalsQuery: %s, rolesQuery: %s, suspendResume: %s]";
    private final static String securityVaultContentVersion = "Reading security vault data version %s target version is %s";
    private final static String traceDefaultLoginSubject = "defaultLogin, login context: %s, subject: %s";
    private final static String traceFoundEntityFromID = "Found entity from %s: %s, filename: %s";
    private final static String debugRequisiteModuleFailure = "Requisite module %s failed";
    private final static String debugModuleOption = "Module option: %s, value: %s";
    private final static String traceBeginLogout = "Begin logout method";
    private final static String errorLoadingConfigFile = "Exception loading file %s";
    private final static String traceSuccessfulLogInToLDAP = "Logged into LDAP server, context: %s";
    private final static String errorGettingServerAuthConfig = "Error getting ServerAuthConfig for layer %s and appContext %s";
    private final static String debugPasswordNotACertificate = "javax.security.auth.login.password is not a X509Certificate";
    private final static String traceAdditionOfRoleToGroup = "Adding role %s to group %s";
    private final static String traceNoAuditContextFoundForDomain = "No audit context found for security domain %s; using default context";
    private final static String traceImpliesMatchesUncheckedSet = "Allowed: matched unchecked set, permission %s";
    private final static String traceRemoveExcludedPolicy = "removeExcludedPolicy, contextID: %s";
    private final static String warnFailureToCreateUnauthIdentity = "Failed to create custom unauthenticated identity";
    private final static String traceBeginInitialize = "Begin initialize method";
    private final static String errorConvertingUsernameUTF8 = "Failed to convert username to byte[] using UTF-8";
    private final static String traceBeginLoadConfig = "Begin loadConfig, loginConfigURL: %s";
    private final static String debugFailureToResolveEntity = "Cannot resolve entity, systemId: %s, publicId: %s";
    private final static String mixedVaultDataFound = "Security Vault contains both covnerted (%s) and pre-conversion data (%s). Try to delete %s file and start over again.";
    private final static String traceUsingUnauthIdentity = "Authenticating using unauthenticated identity %s";
    private final static String traceBeginResolveSystemID = "Begin resolveSystemId, systemId: %s";
    private final static String warnEndLoadConfigWithFailure = "End loadConfig, failed to load config: %s";
    private final static String traceFoundUserRolesContextDN = "Found user roles context DN: %s";
    private final static String traceCreateDigestCallback = "Created DigestCallback %s";
    private final static String errorGettingServerAuthContext = "Error getting ServerAuthContext for authContextId %s and security domain %s";
    private final static String warnFailureToFindCertForAlias = "Failed to find certificate for alias &%s";
    private final static String traceEndInitialize = "End initialize method";
    private final static String errorCheckingStrongJurisdictionPolicyFiles = "Failed to check if the strong jurisdiction policy files have been installed";
    private final static String debugFailureToCreatePrincipal = "Failed to create principal %s";
    private final static String traceRolesBeforeMapping = "Roles before mapping: %s";
    private final static String traceUnauthenticatedIdentity = "Saw unauthenticated indentity: %s";
    private final static String traceProtectionDomainPrincipals = "Protection domain principals: %s";
    private final static String traceRegisterPolicy = "Registered policy for contextID: %s, type: %s, location: %s";
    private final static String traceRolesDNSearch = "Searching rolesCtxDN %s with roleFilter: %s, filterArgs: %s, roleAttr: %s, searchScope: %s, searchTimeLimit: %s";
    private final static String traceRejectingEmptyPassword = "Rejecting empty password as allowEmptyPasswords option has not been set to true";
    private final static String traceLinkConfiguration = "linkConfiguration, link to contextID: %s";
    private final static String traceBeginValidateCache = "Begin validateCache, domainInfo: %s, credential class: %s";
    private final static String traceHostThreadLocalGet = "Returning host %s from thread [id: %s]";
    private final static String traceAddPermissionsToUncheckedPolicy = "addToUncheckedPolicy, permission collection: %s";
    private final static String debugMappingProviderOptions = "Mapping provider options [principal: %s, principal to roles map: %s, subject principals: %s]";
    private final static String debugRealHostForTrust = "The real host for trust is %s";
    private final static String traceBeginResolveClasspathName = "Begin resolveClasspathName, systemId: %s";
    private final static String warnModuleCreationWithEmptyPassword = "Creating login module with empty password";
    private final static String debugNullAuthenticationManager = "AuthenticationManager is null for security domain %s";
    private final static String errorUsingDisabledDomain = "The security domain %s has been disabled. All authentication will fail";
    private final static String traceHasResourcePermission = "hasResourcePermission, permission: %s, allowed: %s";
    private final static String traceAddAppConfig = "addAppConfig(%s), AuthInfo: %s";
    private final static String traceGetAppConfigEntryViaParent = "getAppConfigurationEntry(%s), no entry found, trying parent config %s";
    private final static String traceEndGetAppConfigEntryWithFailure = "End getAppConfigurationEntry(%s), failed to find entry";
    private final static String errorCalculatingPasswordHash = "Password hash calculation failed";
    private final static String debugImpliesResult = "Checking result, implies: %s";
    private final static String traceAttemptToLoadResource = "Attempting to load resource %s";
    private final static String traceRolesAfterMapping = "Roles after mapping: %s";
    private final static String tracePropertiesFileLoaded = "Properties file %s loaded, users: %s";
    private final static String traceJSSEDomainGetKey = "JSSE domain got request for key with alias %s";
    private final static String traceJSSEDomainGetCertificate = "JSSE domain got request for certificate with alias %s";
    private final static String traceLDAPConnectionEnv = "Logging into LDAP server with env %s";
    private final static String warnFailureToFindConfig = "Failed to find config: %s";
    private final static String infoVaultInitialized = "Default Security Vault Implementation Initialized and Ready";
    private final static String warnInvalidModuleOption = "Invalid or misspelled module option: %s";
    private final static String keyStoreConvertedToJCEKS = "Security Vault key store successfuly converted to JCEKS type (%s). From now on use JCEKS as KEYSTORE_TYPE in Security Vault configuration.";
    private final static String traceSecurityDomainFound = "Found security domain: %s";
    private final static String traceHasRolePermission = "hasRolePermission, permission: %s, allowed: %s";
    private final static String errorCreatingCertificateVerifier = "Failed to create X509CertificateVerifier";
    private final static String warnSecurityMagementNotSet = "SecurityManagement is not set, creating a default one";
    private final static String traceBindDNNotFound = "bindDN is not found";
    private final static String traceBeginLogin = "Begin login method";
    private final static String traceGetAppConfigEntryViaDefault = "getAppConfigurationEntry(%s), no entry in parent config, trying default %s";
    private final static String errorLoadingUserRolesPropertiesFiles = "Failed to load users/passwords/roles files";
    private final static String traceBeginGetRoleSets = "Begin getRoleSets";
    private final static String debugFailureToParseNumberProperty = "Failed to parse %s as number, using default value %s";
    private final static String errorFindingSecurityDomain = "Unable to find the security domain %s";
    private final static String debugRequiredModuleFailure = "Required module %s failed";
    private final static String debugFailureToInstantiateClass = "Failed to instantiate class %s";
    private final static String warnFailureToLoadIDFromResource = "Cannot load %s from %s resource: %s";
    private final static String debugFailureToCreateIdentityForAlias = "Failed to create identity for alias %s";
    private final static String traceAddPermissionToExcludedPolicy = "addToExcludedPolicy, permission: %s";
    private final static String traceEndValidateCredential = "End validateCredential method, result: %s";
    private final static String traceFlushWholeCache = "Flushing all entries from security cache";
    private final static String traceEndIsValid = "End isValid, result = %s";

    public PicketBoxLogger_$logger(final Logger log) {
        super(log);
    }

    @Override
    public final void traceEndDoesUserHaveRole(final boolean hasRole) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000330: ")+ traceEndDoesUserHaveRole$str()), hasRole);
    }

    protected String traceEndDoesUserHaveRole$str() {
        return traceEndDoesUserHaveRole;
    }

    @Override
    public final void debugFailureToQueryLDAPAttribute(final String attributeName, final String contextName, final Throwable throwable) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), (throwable), ((projectCode +"000270: ")+ debugFailureToQueryLDAPAttribute$str()), attributeName, contextName);
    }

    protected String debugFailureToQueryLDAPAttribute$str() {
        return debugFailureToQueryLDAPAttribute;
    }

    @Override
    public final void traceBeginIsValid(final Principal principal, final String cacheEntry) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000200: ")+ traceBeginIsValid$str()), principal, cacheEntry);
    }

    protected String traceBeginIsValid$str() {
        return traceBeginIsValid;
    }

    @Override
    public final void debugAuthorizationError(final Throwable throwable) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), (throwable), ((projectCode +"000325: ")+ debugAuthorizationError$str()));
    }

    protected String debugAuthorizationError$str() {
        return debugAuthorizationError;
    }

    @Override
    public final void traceRemoveAppConfig(final String appName) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000227: ")+ traceRemoveAppConfig$str()), appName);
    }

    protected String traceRemoveAppConfig$str() {
        return traceRemoveAppConfig;
    }

    @Override
    public final void traceInsertedCacheInfo(final String cacheInfo) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000208: ")+ traceInsertedCacheInfo$str()), cacheInfo);
    }

    protected String traceInsertedCacheInfo$str() {
        return traceInsertedCacheInfo;
    }

    @Override
    public final void traceCertificateFound(final String serialNumber, final String subjectDN) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000253: ")+ traceCertificateFound$str()), serialNumber, subjectDN);
    }

    protected String traceCertificateFound$str() {
        return traceCertificateFound;
    }

    @Override
    public final void traceObtainedAuthInfoFromHandler(final Principal loginPrincipal, final Class credentialClass) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000351: ")+ traceObtainedAuthInfoFromHandler$str()), loginPrincipal, credentialClass);
    }

    protected String traceObtainedAuthInfoFromHandler$str() {
        return traceObtainedAuthInfoFromHandler;
    }

    @Override
    public final void vaultDoesnotContainSecretKey(final String alias) {
        super.log.logf(FQCN, (Logger.Level.INFO), null, ((projectCode +"000371: ")+ vaultDoesnotContainSecretKey$str()), alias);
    }

    protected String vaultDoesnotContainSecretKey$str() {
        return vaultDoesnotContainSecretKey;
    }

    @Override
    public final void debugFailureToFindAttrInSearchResult(final String attrName, final String searchResult) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), null, ((projectCode +"000277: ")+ debugFailureToFindAttrInSearchResult$str()), attrName, searchResult);
    }

    protected String debugFailureToFindAttrInSearchResult$str() {
        return debugFailureToFindAttrInSearchResult;
    }

    @Override
    public final void traceHasUserDataPermission(final String permission, final boolean allowed) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000297: ")+ traceHasUserDataPermission$str()), permission, allowed);
    }

    protected String traceHasUserDataPermission$str() {
        return traceHasUserDataPermission;
    }

    @Override
    public final void debugErrorGettingRequestFromPolicyContext(final Throwable throwable) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), (throwable), ((projectCode +"000235: ")+ debugErrorGettingRequestFromPolicyContext$str()));
    }

    protected String debugErrorGettingRequestFromPolicyContext$str() {
        return debugErrorGettingRequestFromPolicyContext;
    }

    @Override
    public final void debugLoadConfigAsXML(final URL configURL) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), null, ((projectCode +"000232: ")+ debugLoadConfigAsXML$str()), configURL);
    }

    protected String debugLoadConfigAsXML$str() {
        return debugLoadConfigAsXML;
    }

    @Override
    public final void traceAddPermissionToUncheckedPolicy(final Permission permission) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000312: ")+ traceAddPermissionToUncheckedPolicy$str()), permission);
    }

    protected String traceAddPermissionToUncheckedPolicy$str() {
        return traceAddPermissionToUncheckedPolicy;
    }

    @Override
    public final void debugBadPasswordForUsername(final String username) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), null, ((projectCode +"000283: ")+ debugBadPasswordForUsername$str()), username);
    }

    protected String debugBadPasswordForUsername$str() {
        return debugBadPasswordForUsername;
    }

    @Override
    public final void traceMappedX500Principal(final Principal newPrincipal) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000320: ")+ traceMappedX500Principal$str()), newPrincipal);
    }

    protected String traceMappedX500Principal$str() {
        return traceMappedX500Principal;
    }

    @Override
    public final void traceBeginCommit(final boolean loginOk) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000242: ")+ traceBeginCommit$str()), loginOk);
    }

    protected String traceBeginCommit$str() {
        return traceBeginCommit;
    }

    @Override
    public final void debugJBossPolicyConfigurationConstruction(final String contextID) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), null, ((projectCode +"000307: ")+ debugJBossPolicyConfigurationConstruction$str()), contextID);
    }

    protected String debugJBossPolicyConfigurationConstruction$str() {
        return debugJBossPolicyConfigurationConstruction;
    }

    @Override
    public final void debugFailureToExecuteRolesDNSearch(final Throwable throwable) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), (throwable), ((projectCode +"000278: ")+ debugFailureToExecuteRolesDNSearch$str()));
    }

    protected String debugFailureToExecuteRolesDNSearch$str() {
        return debugFailureToExecuteRolesDNSearch;
    }

    @Override
    public final void unsupportedHashEncodingFormat(final String hashEncoding) {
        super.log.logf(FQCN, (Logger.Level.ERROR), null, ((projectCode +"000215: ")+ unsupportedHashEncodingFormat$str()), hashEncoding);
    }

    protected String unsupportedHashEncodingFormat$str() {
        return unsupportedHashEncodingFormat;
    }

    @Override
    public final void wrongBase64StringUsed(final String fixedBase64) {
        super.log.logf(FQCN, (Logger.Level.WARN), null, ((projectCode +"000376: ")+ wrongBase64StringUsed$str()), fixedBase64);
    }

    protected String wrongBase64StringUsed$str() {
        return wrongBase64StringUsed;
    }

    @Override
    public final void errorGettingModuleInformation(final Throwable cause) {
        super.log.logf(FQCN, (Logger.Level.ERROR), (cause), ((projectCode +"000375: ")+ errorGettingModuleInformation$str()));
    }

    protected String errorGettingModuleInformation$str() {
        return errorGettingModuleInformation;
    }

    @Override
    public final void traceSecRolesAssociationSetSecurityRoles(final Map roles) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000354: ")+ traceSecRolesAssociationSetSecurityRoles$str()), roles);
    }

    protected String traceSecRolesAssociationSetSecurityRoles$str() {
        return traceSecRolesAssociationSetSecurityRoles;
    }

    @Override
    public final void debugFailureToLoadPropertiesFile(final String fileName, final Throwable throwable) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), (throwable), ((projectCode +"000280: ")+ debugFailureToLoadPropertiesFile$str()), fileName);
    }

    protected String debugFailureToLoadPropertiesFile$str() {
        return debugFailureToLoadPropertiesFile;
    }

    @Override
    public final void traceDefaultLoginPrincipal(final Principal principal) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000209: ")+ traceDefaultLoginPrincipal$str()), principal);
    }

    protected String traceDefaultLoginPrincipal$str() {
        return traceDefaultLoginPrincipal;
    }

    @Override
    public final void debugIgnoredException(final Throwable throwable) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), (throwable), ((projectCode +"000293: ")+ debugIgnoredException$str()));
    }

    protected String debugIgnoredException$str() {
        return debugIgnoredException;
    }

    @Override
    public final void errorCannotGetMD5AlgorithmInstance() {
        super.log.logf(FQCN, (Logger.Level.ERROR), null, ((projectCode +"000362: ")+ errorCannotGetMD5AlgorithmInstance$str()));
    }

    protected String errorCannotGetMD5AlgorithmInstance$str() {
        return errorCannotGetMD5AlgorithmInstance;
    }

    @Override
    public final void traceDeregisterPolicy(final String contextID, final String type) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000333: ")+ traceDeregisterPolicy$str()), contextID, type);
    }

    protected String traceDeregisterPolicy$str() {
        return traceDeregisterPolicy;
    }

    @Override
    public final void traceCurrentCallingPrincipal(final String username, final String threadName) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000359: ")+ traceCurrentCallingPrincipal$str()), username, threadName);
    }

    protected String traceCurrentCallingPrincipal$str() {
        return traceCurrentCallingPrincipal;
    }

    @Override
    public final void traceAddPermissionToRole(final Permission permission) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000310: ")+ traceAddPermissionToRole$str()), permission);
    }

    protected String traceAddPermissionToRole$str() {
        return traceAddPermissionToRole;
    }

    @Override
    public final void traceBeginResolvePublicID(final String publicId) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000341: ")+ traceBeginResolvePublicID$str()), publicId);
    }

    protected String traceBeginResolvePublicID$str() {
        return traceBeginResolvePublicID;
    }

    @Override
    public final void traceMappedSystemIdToFilename(final String filename) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000348: ")+ traceMappedSystemIdToFilename$str()), filename);
    }

    protected String traceMappedSystemIdToFilename$str() {
        return traceMappedSystemIdToFilename;
    }

    @Override
    public final void traceResettingCache() {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000365: ")+ traceResettingCache$str()));
    }

    protected String traceResettingCache$str() {
        return traceResettingCache;
    }

    @Override
    public final void traceBeginGetIdentity(final String username) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000357: ")+ traceBeginGetIdentity$str()), username);
    }

    protected String traceBeginGetIdentity$str() {
        return traceBeginGetIdentity;
    }

    @Override
    public final void traceFollowRoleDN(final String roleDN) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000276: ")+ traceFollowRoleDN$str()), roleDN);
    }

    protected String traceFollowRoleDN$str() {
        return traceFollowRoleDN;
    }

    @Override
    public final void traceBeginGetAppConfigEntry(final String appName, final int size) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000221: ")+ traceBeginGetAppConfigEntry$str()), appName, size);
    }

    protected String traceBeginGetAppConfigEntry$str() {
        return traceBeginGetAppConfigEntry;
    }

    @Override
    public final void tracePolicyConfigurationCommit(final String contextID) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000314: ")+ tracePolicyConfigurationCommit$str()), contextID);
    }

    protected String tracePolicyConfigurationCommit$str() {
        return tracePolicyConfigurationCommit;
    }

    @Override
    public final void debugImpliesParameters(final String roleName, final Permissions permissions) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), null, ((projectCode +"000304: ")+ debugImpliesParameters$str()), roleName, permissions);
    }

    protected String debugImpliesParameters$str() {
        return debugImpliesParameters;
    }

    @Override
    public final void debugInvalidWebJaccCheck() {
        super.log.logf(FQCN, (Logger.Level.DEBUG), null, ((projectCode +"000294: ")+ debugInvalidWebJaccCheck$str()));
    }

    protected String debugInvalidWebJaccCheck$str() {
        return debugInvalidWebJaccCheck;
    }

    @Override
    public final void traceStoringPasswordToCache(final String newKey) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000364: ")+ traceStoringPasswordToCache$str()), newKey);
    }

    protected String traceStoringPasswordToCache$str() {
        return traceStoringPasswordToCache;
    }

    @Override
    public final void debugInsufficientMethodPermissions(final Principal ejbPrincipal, final String ejbName, final String methodName, final String interfaceName, final String requiredRoles, final String principalRoles, final String runAsRoles) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), null, ((projectCode +"000292: ")+ debugInsufficientMethodPermissions$str()), ejbPrincipal, ejbName, methodName, interfaceName, requiredRoles, principalRoles, runAsRoles);
    }

    protected String debugInsufficientMethodPermissions$str() {
        return debugInsufficientMethodPermissions;
    }

    @Override
    public final void ambiguosKeyForSecurityVaultTransformation(final String delimiter, final String vaultBlock, final String attributeName) {
        super.log.logf(FQCN, (Logger.Level.INFO), null, ((projectCode +"000369: ")+ ambiguosKeyForSecurityVaultTransformation$str()), delimiter, vaultBlock, attributeName);
    }

    protected String ambiguosKeyForSecurityVaultTransformation$str() {
        return ambiguosKeyForSecurityVaultTransformation;
    }

    @Override
    public final void traceExecuteQuery(final String query, final String username) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000263: ")+ traceExecuteQuery$str()), query, username);
    }

    protected String traceExecuteQuery$str() {
        return traceExecuteQuery;
    }

    @Override
    public final void debugFailedLogin(final Throwable t) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), (t), ((projectCode +"000206: ")+ debugFailedLogin$str()));
    }

    protected String debugFailedLogin$str() {
        return debugFailedLogin;
    }

    @Override
    public final void cannotDeleteOriginalVaultFile(final String file) {
        super.log.logf(FQCN, (Logger.Level.WARN), null, ((projectCode +"000370: ")+ cannotDeleteOriginalVaultFile$str()), file);
    }

    protected String cannotDeleteOriginalVaultFile$str() {
        return cannotDeleteOriginalVaultFile;
    }

    @Override
    public final void errorGettingJSSESecurityDomain(final String domain) {
        super.log.logf(FQCN, (Logger.Level.ERROR), null, ((projectCode +"000246: ")+ errorGettingJSSESecurityDomain$str()), domain);
    }

    protected String errorGettingJSSESecurityDomain$str() {
        return errorGettingJSSESecurityDomain;
    }

    @Override
    public final void traceEndGetAliasAndCert() {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000255: ")+ traceEndGetAliasAndCert$str()));
    }

    protected String traceEndGetAliasAndCert$str() {
        return traceEndGetAliasAndCert;
    }

    @Override
    public final void traceHostThreadLocalSet(final String host, final long threadId) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000328: ")+ traceHostThreadLocalSet$str()), host, threadId);
    }

    protected String traceHostThreadLocalSet$str() {
        return traceHostThreadLocalSet;
    }

    @Override
    public final void errorDecryptingBindCredential(final Throwable throwable) {
        super.log.logf(FQCN, (Logger.Level.ERROR), (throwable), ((projectCode +"000219: ")+ errorDecryptingBindCredential$str()));
    }

    protected String errorDecryptingBindCredential$str() {
        return errorDecryptingBindCredential;
    }

    @Override
    public final void debugLoadConfigAsSun(final URL configURL, final Throwable throwable) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), (throwable), ((projectCode +"000233: ")+ debugLoadConfigAsSun$str()), configURL);
    }

    protected String debugLoadConfigAsSun$str() {
        return debugLoadConfigAsSun;
    }

    @Override
    public final void traceUpdateCache(final String inputSubject, final String cachedSubject) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000207: ")+ traceUpdateCache$str()), inputSubject, cachedSubject);
    }

    protected String traceUpdateCache$str() {
        return traceUpdateCache;
    }

    @Override
    public final void errorParsingTimeoutNumber() {
        super.log.logf(FQCN, (Logger.Level.ERROR), null, ((projectCode +"000366: ")+ errorParsingTimeoutNumber$str()));
    }

    protected String errorParsingTimeoutNumber$str() {
        return errorParsingTimeoutNumber;
    }

    @Override
    public final void warnResolvingSystemIdAsNonFileURL(final String systemId) {
        super.log.logf(FQCN, (Logger.Level.WARN), null, ((projectCode +"000346: ")+ warnResolvingSystemIdAsNonFileURL$str()), systemId);
    }

    protected String warnResolvingSystemIdAsNonFileURL$str() {
        return warnResolvingSystemIdAsNonFileURL;
    }

    @Override
    public final void traceAddPermissionsToExcludedPolicy(final PermissionCollection permissions) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000309: ")+ traceAddPermissionsToExcludedPolicy$str()), permissions);
    }

    protected String traceAddPermissionsToExcludedPolicy$str() {
        return traceAddPermissionsToExcludedPolicy;
    }

    @Override
    public final void traceBeginDoesUserHaveRole(final Principal principal, final String roles) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000329: ")+ traceBeginDoesUserHaveRole$str()), principal, roles);
    }

    protected String traceBeginDoesUserHaveRole$str() {
        return traceBeginDoesUserHaveRole;
    }

    @Override
    public final void traceImpliesMatchesExcludedSet(final Permission permission) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000300: ")+ traceImpliesMatchesExcludedSet$str()), permission);
    }

    protected String traceImpliesMatchesExcludedSet$str() {
        return traceImpliesMatchesExcludedSet;
    }

    @Override
    public final void traceNoMethodPermissions(final String methodName, final String interfaceName) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000290: ")+ traceNoMethodPermissions$str()), methodName, interfaceName);
    }

    protected String traceNoMethodPermissions$str() {
        return traceNoMethodPermissions;
    }

    @Override
    public final void debugFailureExecutingMethod(final String methodName, final Throwable throwable) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), (throwable), ((projectCode +"000326: ")+ debugFailureExecutingMethod$str()), methodName);
    }

    protected String debugFailureExecutingMethod$str() {
        return debugFailureExecutingMethod;
    }

    @Override
    public final void traceNoPrincipalsInProtectionDomain(final ProtectionDomain domain) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000303: ")+ traceNoPrincipalsInProtectionDomain$str()), domain);
    }

    protected String traceNoPrincipalsInProtectionDomain$str() {
        return traceNoPrincipalsInProtectionDomain;
    }

    @Override
    public final void traceStateMachineNextState(final String action, final String nextState) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000337: ")+ traceStateMachineNextState$str()), action, nextState);
    }

    protected String traceStateMachineNextState$str() {
        return traceStateMachineNextState;
    }

    @Override
    public final void tracePolicyConfigurationDelete(final String contextID) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000315: ")+ tracePolicyConfigurationDelete$str()), contextID);
    }

    protected String tracePolicyConfigurationDelete$str() {
        return tracePolicyConfigurationDelete;
    }

    @Override
    public final void traceRemoveRole(final String roleName, final String contextID) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000318: ")+ traceRemoveRole$str()), roleName, contextID);
    }

    protected String traceRemoveRole$str() {
        return traceRemoveRole;
    }

    @Override
    public final void debugPasswordHashing(final String algorithm, final String encoding, final String charset, final String callback, final String storeCallBack) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), null, ((projectCode +"000281: ")+ debugPasswordHashing$str()), algorithm, encoding, charset, callback, storeCallBack);
    }

    protected String debugPasswordHashing$str() {
        return debugPasswordHashing;
    }

    @Override
    public final void debugEJBPolicyModuleDelegateState(final String methodName, final String interfaceName, final String requiredRoles) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), null, ((projectCode +"000291: ")+ debugEJBPolicyModuleDelegateState$str()), methodName, interfaceName, requiredRoles);
    }

    protected String debugEJBPolicyModuleDelegateState$str() {
        return debugEJBPolicyModuleDelegateState;
    }

    @Override
    public final void traceBeginValidateCredential() {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000256: ")+ traceBeginValidateCredential$str()));
    }

    protected String traceBeginValidateCredential$str() {
        return traceBeginValidateCredential;
    }

    @Override
    public final void traceNoPolicyContextForId(final String contextID) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000306: ")+ traceNoPolicyContextForId$str()), contextID);
    }

    protected String traceNoPolicyContextForId$str() {
        return traceNoPolicyContextForId;
    }

    @Override
    public final void traceEndGetAppConfigEntryWithSuccess(final String appName, final String authInfo) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000224: ")+ traceEndGetAppConfigEntryWithSuccess$str()), appName, authInfo);
    }

    protected String traceEndGetAppConfigEntryWithSuccess$str() {
        return traceEndGetAppConfigEntryWithSuccess;
    }

    @Override
    public final void traceQueryWithEmptyResult() {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000321: ")+ traceQueryWithEmptyResult$str()));
    }

    protected String traceQueryWithEmptyResult$str() {
        return traceQueryWithEmptyResult;
    }

    @Override
    public final void traceCacheEntryLogoutFailure(final Throwable t) {
        super.log.logf(FQCN, (Logger.Level.TRACE), (t), ((projectCode +"000211: ")+ traceCacheEntryLogoutFailure$str()));
    }

    protected String traceCacheEntryLogoutFailure$str() {
        return traceCacheEntryLogoutFailure;
    }

    @Override
    public final void debugFailureToOpenPropertiesFromURL(final Throwable throwable) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), (throwable), ((projectCode +"000287: ")+ debugFailureToOpenPropertiesFromURL$str()));
    }

    protected String debugFailureToOpenPropertiesFromURL$str() {
        return debugFailureToOpenPropertiesFromURL;
    }

    @Override
    public final void warnNullCredentialFromCallbackHandler() {
        super.log.logf(FQCN, (Logger.Level.WARN), null, ((projectCode +"000254: ")+ warnNullCredentialFromCallbackHandler$str()));
    }

    protected String warnNullCredentialFromCallbackHandler$str() {
        return warnNullCredentialFromCallbackHandler;
    }

    @Override
    public final void traceBeginResolveSystemIDasURL(final String systemId) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000345: ")+ traceBeginResolveSystemIDasURL$str()), systemId);
    }

    protected String traceBeginResolveSystemIDasURL$str() {
        return traceBeginResolveSystemIDasURL;
    }

    @Override
    public final void traceRemoveUncheckedPolicy(final String contextID) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000319: ")+ traceRemoveUncheckedPolicy$str()), contextID);
    }

    protected String traceRemoveUncheckedPolicy$str() {
        return traceRemoveUncheckedPolicy;
    }

    @Override
    public final void traceEndLogin(final boolean loginOk) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000241: ")+ traceEndLogin$str()), loginOk);
    }

    protected String traceEndLogin$str() {
        return traceEndLogin;
    }

    @Override
    public final void traceEndLoadConfigWithSuccess(final URL configURL) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000230: ")+ traceEndLoadConfigWithSuccess$str()), configURL);
    }

    protected String traceEndLoadConfigWithSuccess$str() {
        return traceEndLoadConfigWithSuccess;
    }

    @Override
    public final void traceFlushCacheEntry(final String key) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000203: ")+ traceFlushCacheEntry$str()), key);
    }

    protected String traceFlushCacheEntry$str() {
        return traceFlushCacheEntry;
    }

    @Override
    public final void traceBindingLDAPUsername(final String username) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000266: ")+ traceBindingLDAPUsername$str()), username);
    }

    protected String traceBindingLDAPUsername$str() {
        return traceBindingLDAPUsername;
    }

    @Override
    public final void traceLogoutSubject(final String loginContext, final String subject) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000377: ")+ traceLogoutSubject$str()), loginContext, subject);
    }

    protected String traceLogoutSubject$str() {
        return traceLogoutSubject;
    }

    @Override
    public final void errorFindingCharset(final String charSet, final Throwable throwable) {
        super.log.logf(FQCN, (Logger.Level.ERROR), (throwable), ((projectCode +"000214: ")+ errorFindingCharset$str()), charSet);
    }

    protected String errorFindingCharset$str() {
        return errorFindingCharset;
    }

    @Override
    public final void debugJACCDeniedAccess(final String permission, final Subject caller, final String roles) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), null, ((projectCode +"000289: ")+ debugJACCDeniedAccess$str()), permission, caller, roles);
    }

    protected String debugJACCDeniedAccess$str() {
        return debugJACCDeniedAccess;
    }

    @Override
    public final void traceEndValidteCache(final boolean isValid) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000205: ")+ traceEndValidteCache$str()), isValid);
    }

    protected String traceEndValidteCache$str() {
        return traceEndValidteCache;
    }

    @Override
    public final void traceCheckSearchResult(final String searchResult) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000275: ")+ traceCheckSearchResult$str()), searchResult);
    }

    protected String traceCheckSearchResult$str() {
        return traceCheckSearchResult;
    }

    @Override
    public final void traceAssignUserToRole(final String role) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000268: ")+ traceAssignUserToRole$str()), role);
    }

    protected String traceAssignUserToRole$str() {
        return traceAssignUserToRole;
    }

    @Override
    public final void traceEndExecPasswordCmd(final int exitCode) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000356: ")+ traceEndExecPasswordCmd$str()), exitCode);
    }

    protected String traceEndExecPasswordCmd$str() {
        return traceEndExecPasswordCmd;
    }

    @Override
    public final void traceBeginExecPasswordCmd(final String passwordCmd) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000355: ")+ traceBeginExecPasswordCmd$str()), passwordCmd);
    }

    protected String traceBeginExecPasswordCmd$str() {
        return traceBeginExecPasswordCmd;
    }

    @Override
    public final void traceMappedResourceToURL(final String resource, final URL url) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000349: ")+ traceMappedResourceToURL$str()), resource, url);
    }

    protected String traceMappedResourceToURL$str() {
        return traceMappedResourceToURL;
    }

    @Override
    public final void traceIgnoreXMLAttribute(final String uri, final String qName, final String value) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000338: ")+ traceIgnoreXMLAttribute$str()), uri, qName, value);
    }

    protected String traceIgnoreXMLAttribute$str() {
        return traceIgnoreXMLAttribute;
    }

    @Override
    public final void traceBeginGetAliasAndCert() {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000252: ")+ traceBeginGetAliasAndCert$str()));
    }

    protected String traceBeginGetAliasAndCert$str() {
        return traceBeginGetAliasAndCert;
    }

    @Override
    public final void traceRebindWithConfiguredPrincipal(final String principal) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000272: ")+ traceRebindWithConfiguredPrincipal$str()), principal);
    }

    protected String traceRebindWithConfiguredPrincipal$str() {
        return traceRebindWithConfiguredPrincipal;
    }

    @Override
    public final void warnFailureToValidateCertificate() {
        super.log.logf(FQCN, (Logger.Level.WARN), null, ((projectCode +"000259: ")+ warnFailureToValidateCertificate$str()));
    }

    protected String warnFailureToValidateCertificate$str() {
        return warnFailureToValidateCertificate;
    }

    @Override
    public final void debugNullAuthorizationManager(final String securityDomain) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), null, ((projectCode +"000324: ")+ debugNullAuthorizationManager$str()), securityDomain);
    }

    protected String debugNullAuthorizationManager$str() {
        return debugNullAuthorizationManager;
    }

    @Override
    public final void traceSystemIDMismatch(final String systemId, final String publicId, final String registeredId) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000339: ")+ traceSystemIDMismatch$str()), systemId, publicId, registeredId);
    }

    protected String traceSystemIDMismatch$str() {
        return traceSystemIDMismatch;
    }

    @Override
    public final void traceAddPermissionsToRole(final PermissionCollection permissions) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000311: ")+ traceAddPermissionsToRole$str()), permissions);
    }

    protected String traceAddPermissionsToRole$str() {
        return traceAddPermissionsToRole;
    }

    @Override
    public final void traceBeginAbort() {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000244: ")+ traceBeginAbort$str()));
    }

    protected String traceBeginAbort$str() {
        return traceBeginAbort;
    }

    @Override
    public final void traceRetrievingPasswordFromCache(final String newKey) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000363: ")+ traceRetrievingPasswordFromCache$str()), newKey);
    }

    protected String traceRetrievingPasswordFromCache$str() {
        return traceRetrievingPasswordFromCache;
    }

    @Override
    public final void traceValidatingUsingVerifier(final Class verifier) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000257: ")+ traceValidatingUsingVerifier$str()), verifier);
    }

    protected String traceValidatingUsingVerifier$str() {
        return traceValidatingUsingVerifier;
    }

    @Override
    public final void traceDBCertLoginModuleOptions(final String dsJNDIName, final String principalsQuery, final String rolesQuery, final boolean suspendResume) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000262: ")+ traceDBCertLoginModuleOptions$str()), dsJNDIName, principalsQuery, rolesQuery, suspendResume);
    }

    protected String traceDBCertLoginModuleOptions$str() {
        return traceDBCertLoginModuleOptions;
    }

    @Override
    public final void securityVaultContentVersion(final String dataVersion, final String targetVersion) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), null, ((projectCode +"000367: ")+ securityVaultContentVersion$str()), dataVersion, targetVersion);
    }

    protected String securityVaultContentVersion$str() {
        return securityVaultContentVersion;
    }

    @Override
    public final void traceDefaultLoginSubject(final String loginContext, final String subject) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000210: ")+ traceDefaultLoginSubject$str()), loginContext, subject);
    }

    protected String traceDefaultLoginSubject$str() {
        return traceDefaultLoginSubject;
    }

    @Override
    public final void traceFoundEntityFromID(final String idName, final String idValue, final String fileName) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000342: ")+ traceFoundEntityFromID$str()), idName, idValue, fileName);
    }

    protected String traceFoundEntityFromID$str() {
        return traceFoundEntityFromID;
    }

    @Override
    public final void debugRequisiteModuleFailure(final String moduleName) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), null, ((projectCode +"000298: ")+ debugRequisiteModuleFailure$str()), moduleName);
    }

    protected String debugRequisiteModuleFailure$str() {
        return debugRequisiteModuleFailure;
    }

    @Override
    public final void debugModuleOption(final String optionName, final Object optionValue) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), null, ((projectCode +"000350: ")+ debugModuleOption$str()), optionName, optionValue);
    }

    protected String debugModuleOption$str() {
        return debugModuleOption;
    }

    @Override
    public final void traceBeginLogout() {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000243: ")+ traceBeginLogout$str()));
    }

    protected String traceBeginLogout$str() {
        return traceBeginLogout;
    }

    @Override
    public final void errorLoadingConfigFile(final String filename, final Throwable throwable) {
        super.log.logf(FQCN, (Logger.Level.ERROR), (throwable), ((projectCode +"000212: ")+ errorLoadingConfigFile$str()), filename);
    }

    protected String errorLoadingConfigFile$str() {
        return errorLoadingConfigFile;
    }

    @Override
    public final void traceSuccessfulLogInToLDAP(final String context) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000271: ")+ traceSuccessfulLogInToLDAP$str()), context);
    }

    protected String traceSuccessfulLogInToLDAP$str() {
        return traceSuccessfulLogInToLDAP;
    }

    @Override
    public final void errorGettingServerAuthConfig(final String layer, final String appContext, final Throwable cause) {
        super.log.logf(FQCN, (Logger.Level.ERROR), (cause), ((projectCode +"000373: ")+ errorGettingServerAuthConfig$str()), layer, appContext);
    }

    protected String errorGettingServerAuthConfig$str() {
        return errorGettingServerAuthConfig;
    }

    @Override
    public final void debugPasswordNotACertificate() {
        super.log.logf(FQCN, (Logger.Level.DEBUG), null, ((projectCode +"000249: ")+ debugPasswordNotACertificate$str()));
    }

    protected String debugPasswordNotACertificate$str() {
        return debugPasswordNotACertificate;
    }

    @Override
    public final void traceAdditionOfRoleToGroup(final String roleName, final String groupName) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000285: ")+ traceAdditionOfRoleToGroup$str()), roleName, groupName);
    }

    protected String traceAdditionOfRoleToGroup$str() {
        return traceAdditionOfRoleToGroup;
    }

    @Override
    public final void traceNoAuditContextFoundForDomain(final String securityDomain) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000323: ")+ traceNoAuditContextFoundForDomain$str()), securityDomain);
    }

    protected String traceNoAuditContextFoundForDomain$str() {
        return traceNoAuditContextFoundForDomain;
    }

    @Override
    public final void traceImpliesMatchesUncheckedSet(final Permission permission) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000301: ")+ traceImpliesMatchesUncheckedSet$str()), permission);
    }

    protected String traceImpliesMatchesUncheckedSet$str() {
        return traceImpliesMatchesUncheckedSet;
    }

    @Override
    public final void traceRemoveExcludedPolicy(final String contextID) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000317: ")+ traceRemoveExcludedPolicy$str()), contextID);
    }

    protected String traceRemoveExcludedPolicy$str() {
        return traceRemoveExcludedPolicy;
    }

    @Override
    public final void warnFailureToCreateUnauthIdentity(final Throwable throwable) {
        super.log.logf(FQCN, (Logger.Level.WARN), (throwable), ((projectCode +"000238: ")+ warnFailureToCreateUnauthIdentity$str()));
    }

    protected String warnFailureToCreateUnauthIdentity$str() {
        return warnFailureToCreateUnauthIdentity;
    }

    @Override
    public final void traceBeginInitialize() {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000236: ")+ traceBeginInitialize$str()));
    }

    protected String traceBeginInitialize$str() {
        return traceBeginInitialize;
    }

    @Override
    public final void errorConvertingUsernameUTF8(final Throwable throwable) {
        super.log.logf(FQCN, (Logger.Level.ERROR), (throwable), ((projectCode +"000213: ")+ errorConvertingUsernameUTF8$str()));
    }

    protected String errorConvertingUsernameUTF8$str() {
        return errorConvertingUsernameUTF8;
    }

    @Override
    public final void traceBeginLoadConfig(final URL configURL) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000229: ")+ traceBeginLoadConfig$str()), configURL);
    }

    protected String traceBeginLoadConfig$str() {
        return traceBeginLoadConfig;
    }

    @Override
    public final void debugFailureToResolveEntity(final String systemId, final String publicId) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), null, ((projectCode +"000340: ")+ debugFailureToResolveEntity$str()), systemId, publicId);
    }

    protected String debugFailureToResolveEntity$str() {
        return debugFailureToResolveEntity;
    }

    @Override
    public final void mixedVaultDataFound(final String vaultDatFile, final String encDatFile, final String encDatFile2) {
        super.log.logf(FQCN, (Logger.Level.ERROR), null, ((projectCode +"000368: ")+ mixedVaultDataFound$str()), vaultDatFile, encDatFile, encDatFile2);
    }

    protected String mixedVaultDataFound$str() {
        return mixedVaultDataFound;
    }

    @Override
    public final void traceUsingUnauthIdentity(final String unauthenticatedIdentity) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000250: ")+ traceUsingUnauthIdentity$str()), unauthenticatedIdentity);
    }

    protected String traceUsingUnauthIdentity$str() {
        return traceUsingUnauthIdentity;
    }

    @Override
    public final void traceBeginResolveSystemID(final String systemId) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000344: ")+ traceBeginResolveSystemID$str()), systemId);
    }

    protected String traceBeginResolveSystemID$str() {
        return traceBeginResolveSystemID;
    }

    @Override
    public final void warnEndLoadConfigWithFailure(final URL configURL, final Throwable throwable) {
        super.log.logf(FQCN, (Logger.Level.WARN), (throwable), ((projectCode +"000231: ")+ warnEndLoadConfigWithFailure$str()), configURL);
    }

    protected String warnEndLoadConfigWithFailure$str() {
        return warnEndLoadConfigWithFailure;
    }

    @Override
    public final void traceFoundUserRolesContextDN(final String context) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000273: ")+ traceFoundUserRolesContextDN$str()), context);
    }

    protected String traceFoundUserRolesContextDN$str() {
        return traceFoundUserRolesContextDN;
    }

    @Override
    public final void traceCreateDigestCallback(final String callback) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000284: ")+ traceCreateDigestCallback$str()), callback);
    }

    protected String traceCreateDigestCallback$str() {
        return traceCreateDigestCallback;
    }

    @Override
    public final void errorGettingServerAuthContext(final String authContextId, final String securityDomain, final Throwable cause) {
        super.log.logf(FQCN, (Logger.Level.ERROR), (cause), ((projectCode +"000374: ")+ errorGettingServerAuthContext$str()), authContextId, securityDomain);
    }

    protected String errorGettingServerAuthContext$str() {
        return errorGettingServerAuthContext;
    }

    @Override
    public final void warnFailureToFindCertForAlias(final String alias, final Throwable throwable) {
        super.log.logf(FQCN, (Logger.Level.WARN), (throwable), ((projectCode +"000258: ")+ warnFailureToFindCertForAlias$str()), alias);
    }

    protected String warnFailureToFindCertForAlias$str() {
        return warnFailureToFindCertForAlias;
    }

    @Override
    public final void traceEndInitialize() {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000239: ")+ traceEndInitialize$str()));
    }

    protected String traceEndInitialize$str() {
        return traceEndInitialize;
    }

    @Override
    public final void errorCheckingStrongJurisdictionPolicyFiles(final Throwable throwable) {
        super.log.logf(FQCN, (Logger.Level.ERROR), (throwable), ((projectCode +"000217: ")+ errorCheckingStrongJurisdictionPolicyFiles$str()));
    }

    protected String errorCheckingStrongJurisdictionPolicyFiles$str() {
        return errorCheckingStrongJurisdictionPolicyFiles;
    }

    @Override
    public final void debugFailureToCreatePrincipal(final String name, final Throwable throwable) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), (throwable), ((projectCode +"000264: ")+ debugFailureToCreatePrincipal$str()), name);
    }

    protected String debugFailureToCreatePrincipal$str() {
        return debugFailureToCreatePrincipal;
    }

    @Override
    public final void traceRolesBeforeMapping(final String roles) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000331: ")+ traceRolesBeforeMapping$str()), roles);
    }

    protected String traceRolesBeforeMapping$str() {
        return traceRolesBeforeMapping;
    }

    @Override
    public final void traceUnauthenticatedIdentity(final String name) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000237: ")+ traceUnauthenticatedIdentity$str()), name);
    }

    protected String traceUnauthenticatedIdentity$str() {
        return traceUnauthenticatedIdentity;
    }

    @Override
    public final void traceProtectionDomainPrincipals(final List principalNames) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000302: ")+ traceProtectionDomainPrincipals$str()), principalNames);
    }

    protected String traceProtectionDomainPrincipals$str() {
        return traceProtectionDomainPrincipals;
    }

    @Override
    public final void traceRegisterPolicy(final String contextID, final String type, final String location) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000334: ")+ traceRegisterPolicy$str()), contextID, type, location);
    }

    protected String traceRegisterPolicy$str() {
        return traceRegisterPolicy;
    }

    @Override
    public final void traceRolesDNSearch(final String dn, final String roleFilter, final String filterArgs, final String roleAttr, final int searchScope, final int searchTimeLimit) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000274: ")+ traceRolesDNSearch$str()), dn, roleFilter, filterArgs, roleAttr, searchScope, searchTimeLimit);
    }

    protected String traceRolesDNSearch$str() {
        return traceRolesDNSearch;
    }

    @Override
    public final void traceRejectingEmptyPassword() {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000267: ")+ traceRejectingEmptyPassword$str()));
    }

    protected String traceRejectingEmptyPassword$str() {
        return traceRejectingEmptyPassword;
    }

    @Override
    public final void traceLinkConfiguration(final String contextID) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000316: ")+ traceLinkConfiguration$str()), contextID);
    }

    protected String traceLinkConfiguration$str() {
        return traceLinkConfiguration;
    }

    @Override
    public final void traceBeginValidateCache(final String info, final Class credentialClass) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000204: ")+ traceBeginValidateCache$str()), info, credentialClass);
    }

    protected String traceBeginValidateCache$str() {
        return traceBeginValidateCache;
    }

    @Override
    public final void traceHostThreadLocalGet(final String host, final long threadId) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000327: ")+ traceHostThreadLocalGet$str()), host, threadId);
    }

    protected String traceHostThreadLocalGet$str() {
        return traceHostThreadLocalGet;
    }

    @Override
    public final void traceAddPermissionsToUncheckedPolicy(final PermissionCollection permissions) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000313: ")+ traceAddPermissionsToUncheckedPolicy$str()), permissions);
    }

    protected String traceAddPermissionsToUncheckedPolicy$str() {
        return traceAddPermissionsToUncheckedPolicy;
    }

    @Override
    public final void debugMappingProviderOptions(final Principal principal, final Map principalRolesMap, final Set subjectPrincipals) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), null, ((projectCode +"000322: ")+ debugMappingProviderOptions$str()), principal, principalRolesMap, subjectPrincipals);
    }

    protected String debugMappingProviderOptions$str() {
        return debugMappingProviderOptions;
    }

    @Override
    public final void debugRealHostForTrust(final String host) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), null, ((projectCode +"000279: ")+ debugRealHostForTrust$str()), host);
    }

    protected String debugRealHostForTrust$str() {
        return debugRealHostForTrust;
    }

    @Override
    public final void traceBeginResolveClasspathName(final String systemId) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000347: ")+ traceBeginResolveClasspathName$str()), systemId);
    }

    protected String traceBeginResolveClasspathName$str() {
        return traceBeginResolveClasspathName;
    }

    @Override
    public final void warnModuleCreationWithEmptyPassword() {
        super.log.logf(FQCN, (Logger.Level.WARN), null, ((projectCode +"000360: ")+ warnModuleCreationWithEmptyPassword$str()));
    }

    protected String warnModuleCreationWithEmptyPassword$str() {
        return warnModuleCreationWithEmptyPassword;
    }

    @Override
    public final void debugNullAuthenticationManager(final String securityDomain) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), null, ((projectCode +"000336: ")+ debugNullAuthenticationManager$str()), securityDomain);
    }

    protected String debugNullAuthenticationManager$str() {
        return debugNullAuthenticationManager;
    }

    @Override
    public final void errorUsingDisabledDomain(final String securityDomain) {
        super.log.logf(FQCN, (Logger.Level.ERROR), null, ((projectCode +"000265: ")+ errorUsingDisabledDomain$str()), securityDomain);
    }

    protected String errorUsingDisabledDomain$str() {
        return errorUsingDisabledDomain;
    }

    @Override
    public final void traceHasResourcePermission(final String permission, final boolean allowed) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000295: ")+ traceHasResourcePermission$str()), permission, allowed);
    }

    protected String traceHasResourcePermission$str() {
        return traceHasResourcePermission;
    }

    @Override
    public final void traceAddAppConfig(final String appName, final String authInfo) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000226: ")+ traceAddAppConfig$str()), appName, authInfo);
    }

    protected String traceAddAppConfig$str() {
        return traceAddAppConfig;
    }

    @Override
    public final void traceGetAppConfigEntryViaParent(final String appName, final String parentConfig) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000222: ")+ traceGetAppConfigEntryViaParent$str()), appName, parentConfig);
    }

    protected String traceGetAppConfigEntryViaParent$str() {
        return traceGetAppConfigEntryViaParent;
    }

    @Override
    public final void traceEndGetAppConfigEntryWithFailure(final String appName) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000225: ")+ traceEndGetAppConfigEntryWithFailure$str()), appName);
    }

    protected String traceEndGetAppConfigEntryWithFailure$str() {
        return traceEndGetAppConfigEntryWithFailure;
    }

    @Override
    public final void errorCalculatingPasswordHash(final Throwable throwable) {
        super.log.logf(FQCN, (Logger.Level.ERROR), (throwable), ((projectCode +"000216: ")+ errorCalculatingPasswordHash$str()));
    }

    protected String errorCalculatingPasswordHash$str() {
        return errorCalculatingPasswordHash;
    }

    @Override
    public final void debugImpliesResult(final boolean implies) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), null, ((projectCode +"000305: ")+ debugImpliesResult$str()), implies);
    }

    protected String debugImpliesResult$str() {
        return debugImpliesResult;
    }

    @Override
    public final void traceAttemptToLoadResource(final String resourceURL) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000286: ")+ traceAttemptToLoadResource$str()), resourceURL);
    }

    protected String traceAttemptToLoadResource$str() {
        return traceAttemptToLoadResource;
    }

    @Override
    public final void traceRolesAfterMapping(final String roles) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000332: ")+ traceRolesAfterMapping$str()), roles);
    }

    protected String traceRolesAfterMapping$str() {
        return traceRolesAfterMapping;
    }

    @Override
    public final void tracePropertiesFileLoaded(final String fileName, final Set users) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000288: ")+ tracePropertiesFileLoaded$str()), fileName, users);
    }

    protected String tracePropertiesFileLoaded$str() {
        return tracePropertiesFileLoaded;
    }

    @Override
    public final void traceJSSEDomainGetKey(final String alias) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000352: ")+ traceJSSEDomainGetKey$str()), alias);
    }

    protected String traceJSSEDomainGetKey$str() {
        return traceJSSEDomainGetKey;
    }

    @Override
    public final void traceJSSEDomainGetCertificate(final String alias) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000353: ")+ traceJSSEDomainGetCertificate$str()), alias);
    }

    protected String traceJSSEDomainGetCertificate$str() {
        return traceJSSEDomainGetCertificate;
    }

    @Override
    public final void traceLDAPConnectionEnv(final Properties env) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000220: ")+ traceLDAPConnectionEnv$str()), env);
    }

    protected String traceLDAPConnectionEnv$str() {
        return traceLDAPConnectionEnv;
    }

    @Override
    public final void warnFailureToFindConfig(final String loginConfig) {
        super.log.logf(FQCN, (Logger.Level.WARN), null, ((projectCode +"000228: ")+ warnFailureToFindConfig$str()), loginConfig);
    }

    protected String warnFailureToFindConfig$str() {
        return warnFailureToFindConfig;
    }

    @Override
    public final void infoVaultInitialized() {
        super.log.logf(FQCN, (Logger.Level.INFO), null, ((projectCode +"000361: ")+ infoVaultInitialized$str()));
    }

    protected String infoVaultInitialized$str() {
        return infoVaultInitialized;
    }

    @Override
    public final void warnInvalidModuleOption(final String option) {
        super.log.logf(FQCN, (Logger.Level.WARN), null, ((projectCode +"000234: ")+ warnInvalidModuleOption$str()), option);
    }

    protected String warnInvalidModuleOption$str() {
        return warnInvalidModuleOption;
    }

    @Override
    public final void keyStoreConvertedToJCEKS(final String keyStoreFile) {
        super.log.logf(FQCN, (Logger.Level.INFO), null, ((projectCode +"000372: ")+ keyStoreConvertedToJCEKS$str()), keyStoreFile);
    }

    protected String keyStoreConvertedToJCEKS$str() {
        return keyStoreConvertedToJCEKS;
    }

    @Override
    public final void traceSecurityDomainFound(final String domain) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000245: ")+ traceSecurityDomainFound$str()), domain);
    }

    protected String traceSecurityDomainFound$str() {
        return traceSecurityDomainFound;
    }

    @Override
    public final void traceHasRolePermission(final String permission, final boolean allowed) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000296: ")+ traceHasRolePermission$str()), permission, allowed);
    }

    protected String traceHasRolePermission$str() {
        return traceHasRolePermission;
    }

    @Override
    public final void errorCreatingCertificateVerifier(final Throwable throwable) {
        super.log.logf(FQCN, (Logger.Level.ERROR), (throwable), ((projectCode +"000248: ")+ errorCreatingCertificateVerifier$str()));
    }

    protected String errorCreatingCertificateVerifier$str() {
        return errorCreatingCertificateVerifier;
    }

    @Override
    public final void warnSecurityMagementNotSet() {
        super.log.logf(FQCN, (Logger.Level.WARN), null, ((projectCode +"000335: ")+ warnSecurityMagementNotSet$str()));
    }

    protected String warnSecurityMagementNotSet$str() {
        return warnSecurityMagementNotSet;
    }

    @Override
    public final void traceBindDNNotFound() {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000218: ")+ traceBindDNNotFound$str()));
    }

    protected String traceBindDNNotFound$str() {
        return traceBindDNNotFound;
    }

    @Override
    public final void traceBeginLogin() {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000240: ")+ traceBeginLogin$str()));
    }

    protected String traceBeginLogin$str() {
        return traceBeginLogin;
    }

    @Override
    public final void traceGetAppConfigEntryViaDefault(final String appName, final String defaultConfig) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000223: ")+ traceGetAppConfigEntryViaDefault$str()), appName, defaultConfig);
    }

    protected String traceGetAppConfigEntryViaDefault$str() {
        return traceGetAppConfigEntryViaDefault;
    }

    @Override
    public final void errorLoadingUserRolesPropertiesFiles(final Throwable throwable) {
        super.log.logf(FQCN, (Logger.Level.ERROR), (throwable), ((projectCode +"000261: ")+ errorLoadingUserRolesPropertiesFiles$str()));
    }

    protected String errorLoadingUserRolesPropertiesFiles$str() {
        return errorLoadingUserRolesPropertiesFiles;
    }

    @Override
    public final void traceBeginGetRoleSets() {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000358: ")+ traceBeginGetRoleSets$str()));
    }

    protected String traceBeginGetRoleSets$str() {
        return traceBeginGetRoleSets;
    }

    @Override
    public final void debugFailureToParseNumberProperty(final String property, final long defaultValue) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), null, ((projectCode +"000269: ")+ debugFailureToParseNumberProperty$str()), property, defaultValue);
    }

    protected String debugFailureToParseNumberProperty$str() {
        return debugFailureToParseNumberProperty;
    }

    @Override
    public final void errorFindingSecurityDomain(final String domain, final Throwable throwable) {
        super.log.logf(FQCN, (Logger.Level.ERROR), (throwable), ((projectCode +"000247: ")+ errorFindingSecurityDomain$str()), domain);
    }

    protected String errorFindingSecurityDomain$str() {
        return errorFindingSecurityDomain;
    }

    @Override
    public final void debugRequiredModuleFailure(final String moduleName) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), null, ((projectCode +"000299: ")+ debugRequiredModuleFailure$str()), moduleName);
    }

    protected String debugRequiredModuleFailure$str() {
        return debugRequiredModuleFailure;
    }

    @Override
    public final void debugFailureToInstantiateClass(final String className, final Throwable throwable) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), (throwable), ((projectCode +"000282: ")+ debugFailureToInstantiateClass$str()), className);
    }

    protected String debugFailureToInstantiateClass$str() {
        return debugFailureToInstantiateClass;
    }

    @Override
    public final void warnFailureToLoadIDFromResource(final String idName, final String resourceType, final String resourceName) {
        super.log.logf(FQCN, (Logger.Level.WARN), null, ((projectCode +"000343: ")+ warnFailureToLoadIDFromResource$str()), idName, resourceType, resourceName);
    }

    protected String warnFailureToLoadIDFromResource$str() {
        return warnFailureToLoadIDFromResource;
    }

    @Override
    public final void debugFailureToCreateIdentityForAlias(final String alias, final Throwable throwable) {
        super.log.logf(FQCN, (Logger.Level.DEBUG), (throwable), ((projectCode +"000251: ")+ debugFailureToCreateIdentityForAlias$str()), alias);
    }

    protected String debugFailureToCreateIdentityForAlias$str() {
        return debugFailureToCreateIdentityForAlias;
    }

    @Override
    public final void traceAddPermissionToExcludedPolicy(final Permission permission) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000308: ")+ traceAddPermissionToExcludedPolicy$str()), permission);
    }

    protected String traceAddPermissionToExcludedPolicy$str() {
        return traceAddPermissionToExcludedPolicy;
    }

    @Override
    public final void traceEndValidateCredential(final boolean isValid) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000260: ")+ traceEndValidateCredential$str()), isValid);
    }

    protected String traceEndValidateCredential$str() {
        return traceEndValidateCredential;
    }

    @Override
    public final void traceFlushWholeCache() {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000202: ")+ traceFlushWholeCache$str()));
    }

    protected String traceFlushWholeCache$str() {
        return traceFlushWholeCache;
    }

    @Override
    public final void traceEndIsValid(final boolean isValid) {
        super.log.logf(FQCN, (Logger.Level.TRACE), null, ((projectCode +"000201: ")+ traceEndIsValid$str()), isValid);
    }

    protected String traceEndIsValid$str() {
        return traceEndIsValid;
    }

}
