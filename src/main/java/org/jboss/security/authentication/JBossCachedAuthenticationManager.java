package org.jboss.security.authentication;

import java.io.Serializable;
import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.acl.Group;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentMap;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import org.jboss.security.AuthenticationManager;
import org.jboss.security.CacheableManager;
import org.jboss.security.PicketBoxLogger;
import org.jboss.security.PicketBoxMessages;
import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextAssociation;
import org.jboss.security.SecurityContextUtil;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.callback.JBossCallbackHandler;
import org.jboss.security.auth.login.BaseAuthenticationInfo;
import org.jboss.security.config.ApplicationPolicy;
import org.jboss.security.config.SecurityConfiguration;
import org.jboss.security.plugins.ClassLoaderLocator;
import org.jboss.security.plugins.ClassLoaderLocatorFactory;

public class JBossCachedAuthenticationManager
        implements AuthenticationManager, CacheableManager<ConcurrentMap<Principal, JBossCachedAuthenticationManager.DomainInfo>, Principal>
{
    private String securityDomain;
    private CallbackHandler callbackHandler;
    private transient Method setSecurityInfo;
    protected ConcurrentMap<Principal, DomainInfo> domainCache;
    private boolean deepCopySubjectOption = false;

    public JBossCachedAuthenticationManager()
    {
        this("other", new JBossCallbackHandler());
    }

    public JBossCachedAuthenticationManager(String securityDomain, CallbackHandler callbackHandler)
    {
        this.securityDomain = securityDomain;
        this.callbackHandler = callbackHandler;

        Class<?>[] sig = { Principal.class, Object.class };
        try
        {
            this.setSecurityInfo = callbackHandler.getClass().getMethod("setSecurityInfo", sig);
        }
        catch (Exception e)
        {
            throw new UnsupportedOperationException(PicketBoxMessages.MESSAGES.unableToFindSetSecurityInfoMessage());
        }
    }

    public Subject getActiveSubject()
    {
        Subject subj = null;
        SecurityContext sc = SecurityContextAssociation.getSecurityContext();
        if (sc != null) {
            subj = sc.getUtil().getSubject();
        }
        return subj;
    }

    public Principal getTargetPrincipal(Principal anotherDomainPrincipal, Map<String, Object> contextMap)
    {
        throw new UnsupportedOperationException();
    }

    public boolean isValid(Principal principal, Object credential)
    {
        return isValid(principal, credential, null);
    }

    public boolean isValid(Principal principal, Object credential, Subject activeSubject)
    {
        DomainInfo cachedEntry = getCacheInfo(principal != null ? principal : new SimplePrincipal("null"));
        PicketBoxLogger.LOGGER.traceBeginIsValid(principal, cachedEntry != null ? cachedEntry.toString() : null);

        boolean isValid = false;
        if (cachedEntry != null) {
            isValid = validateCache(cachedEntry, credential, activeSubject);
        }
        if (!isValid) {
            isValid = authenticate(principal, credential, activeSubject);
        }
        PicketBoxLogger.LOGGER.traceEndIsValid(isValid);
        return isValid;
    }

    public String getSecurityDomain()
    {
        return this.securityDomain;
    }

    public void flushCache()
    {
        PicketBoxLogger.LOGGER.traceFlushWholeCache();
        if (this.domainCache != null) {
            for (Principal principal : this.domainCache.keySet()) {
                flushCache(principal);
            }
        }
    }

    public void flushCache(Principal key)
    {
        if ((key != null) && (this.domainCache != null) && (this.domainCache.containsKey(key))) {
            logout(key, null);
        }
    }

    public void setCache(ConcurrentMap<Principal, DomainInfo> cache)
    {
        this.domainCache = cache;
    }

    public boolean containsKey(Principal key)
    {
        if ((this.domainCache != null) && (key != null)) {
            return this.domainCache.containsKey(key);
        }
        return false;
    }

    public Set<Principal> getCachedKeys()
    {
        if (this.domainCache != null) {
            return this.domainCache.keySet();
        }
        return null;
    }

    public void setDeepCopySubjectOption(Boolean flag)
    {
        this.deepCopySubjectOption = flag.booleanValue();
    }

    private DomainInfo getCacheInfo(Principal principal)
    {
        if ((this.domainCache != null) && (principal != null)) {
            return (DomainInfo)this.domainCache.get(principal);
        }
        return null;
    }

    private boolean validateCache(DomainInfo info, Object credential, Subject theSubject)
    {
        PicketBoxLogger.LOGGER.traceBeginValidateCache(info.toString(), credential != null ? credential.getClass() : null);

        Object subjectCredential = info.credential;
        boolean isValid = false;
        if ((credential == null) || (subjectCredential == null))
        {
            isValid = (credential == null) && (subjectCredential == null);
        }
        else if (subjectCredential.getClass().isAssignableFrom(credential.getClass()))
        {
            if ((subjectCredential instanceof Comparable))
            {
                Comparable c = (Comparable)subjectCredential;
                isValid = c.compareTo(credential) == 0;
            }
            else if ((subjectCredential instanceof char[]))
            {
                char[] a1 = (char[])subjectCredential;
                char[] a2 = (char[])credential;
                isValid = Arrays.equals(a1, a2);
            }
            else if ((subjectCredential instanceof byte[]))
            {
                byte[] a1 = (byte[])subjectCredential;
                byte[] a2 = (byte[])credential;
                isValid = Arrays.equals(a1, a2);
            }
            else if (subjectCredential.getClass().isArray())
            {
                Object[] a1 = (Object[])subjectCredential;
                Object[] a2 = (Object[])credential;
                isValid = Arrays.equals(a1, a2);
            }
            else
            {
                isValid = subjectCredential.equals(credential);
            }
        }
        else if (((subjectCredential instanceof char[])) && ((credential instanceof String)))
        {
            char[] a1 = (char[])subjectCredential;
            char[] a2 = ((String)credential).toCharArray();
            isValid = Arrays.equals(a1, a2);
        }
        else if (((subjectCredential instanceof String)) && ((credential instanceof char[])))
        {
            char[] a1 = ((String)subjectCredential).toCharArray();
            char[] a2 = (char[])credential;
            isValid = Arrays.equals(a1, a2);
        }
        if (isValid) {
            if (theSubject != null) {
                SubjectActions.copySubject(info.subject, theSubject, false, this.deepCopySubjectOption);
            }
        }
        PicketBoxLogger.LOGGER.traceEndValidteCache(isValid);
        return isValid;
    }

    private boolean authenticate(Principal principal, Object credential, Subject theSubject)
    {
        ApplicationPolicy theAppPolicy = SecurityConfiguration.getApplicationPolicy(this.securityDomain);
        if (theAppPolicy != null)
        {
            BaseAuthenticationInfo authInfo = theAppPolicy.getAuthenticationInfo();
            String jbossModuleName = authInfo.getJBossModuleName();
            if (jbossModuleName != null)
            {
                ClassLoader currentTccl = SubjectActions.getContextClassLoader();
                ClassLoaderLocator theCLL = ClassLoaderLocatorFactory.get();
                if (theCLL != null)
                {
                    ClassLoader newTCCL = theCLL.get(jbossModuleName);
                    if (newTCCL != null) {
                        try
                        {
                            SubjectActions.setContextClassLoader(newTCCL);
                            return proceedWithJaasLogin(principal, credential, theSubject, newTCCL);
                        }
                        finally
                        {
                            SubjectActions.setContextClassLoader(currentTccl);
                        }
                    }
                }
            }
        }
        return proceedWithJaasLogin(principal, credential, theSubject, null);
    }

    private boolean proceedWithJaasLogin(Principal principal, Object credential, Subject theSubject, ClassLoader contextClassLoader)
    {
        Subject subject = null;
        boolean authenticated = false;
        LoginException authException = null;
        try
        {
            LoginContext lc = defaultLogin(principal, credential);
            subject = lc.getSubject();
            if (subject != null)
            {
                if (theSubject != null) {
                    SubjectActions.copySubject(subject, theSubject, false, this.deepCopySubjectOption);
                } else {
                    theSubject = subject;
                }
                authenticated = true;

                updateCache(lc, subject, principal, credential, contextClassLoader);
            }
        }
        catch (LoginException e)
        {
            PicketBoxLogger.LOGGER.debugFailedLogin(e);
            authException = e;
        }
        SubjectActions.setContextInfo("org.jboss.security.exception", authException);

        return authenticated;
    }

    LoginContext defaultLogin(Principal principal, Object credential)
            throws LoginException
    {
        Object[] securityInfo = { principal, credential };
        CallbackHandler theHandler = null;
        LoginContext lc = null;
        try
        {
            theHandler = (CallbackHandler)this.callbackHandler.getClass().newInstance();
            this.setSecurityInfo.invoke(theHandler, securityInfo);
        }
        catch (Throwable e)
        {
            LoginException le = new LoginException(PicketBoxMessages.MESSAGES.unableToFindSetSecurityInfoMessage());
            le.initCause(e);
            throw le;
        }
        try
        {
            Subject subject = new Subject();
            PicketBoxLogger.LOGGER.traceDefaultLoginPrincipal(principal);
            lc = SubjectActions.createLoginContext(this.securityDomain, subject, theHandler);
            lc.login();
            PicketBoxLogger.LOGGER.traceDefaultLoginSubject(lc.toString(), SubjectActions.toString(subject));
        }
        catch (RuntimeException e)
        {
            LoginException le = new LoginException(PicketBoxMessages.MESSAGES.unableToFindSetSecurityInfoMessage());
            le.initCause(e);
            throw le;
        }
        return lc;
    }

    private Subject updateCache(LoginContext loginContext, Subject subject, Principal principal, Object credential, ClassLoader lcClassLoader)
    {
        if (this.domainCache == null) {
            return subject;
        }
        DomainInfo info = new DomainInfo();
        info.loginContext = loginContext;
        info.subject = new Subject();
        SubjectActions.copySubject(subject, info.subject, true, this.deepCopySubjectOption);
        info.credential = credential;
        if (lcClassLoader == null) {
            lcClassLoader = (ClassLoader)AccessController.doPrivileged(new PrivilegedAction()
            {
                public ClassLoader run()
                {
                    ClassLoader loader = Thread.currentThread().getContextClassLoader();
                    if (loader == null) {
                        loader = ClassLoader.getSystemClassLoader();
                    }
                    return loader;
                }
            });
        }
        info.contextClassLoader = lcClassLoader;
        PicketBoxLogger.LOGGER.traceUpdateCache(SubjectActions.toString(subject), SubjectActions.toString(info.subject));

        Set<Group> subjectGroups = subject.getPrincipals(Group.class);
        Iterator<Group> iter = subjectGroups.iterator();
        while (iter.hasNext())
        {
            Group grp = (Group)iter.next();
            String name = grp.getName();
            if (name.equals("CallerPrincipal"))
            {
                Enumeration<? extends Principal> members = grp.members();
                if (members.hasMoreElements()) {
                    info.callerPrincipal = ((Principal)members.nextElement());
                }
            }
        }
        if (info.callerPrincipal == null)
        {
            Set<Principal> subjectPrincipals = subject.getPrincipals(Principal.class);
            Iterator<? extends Principal> iterPrincipals = subjectPrincipals.iterator();
            while (iterPrincipals.hasNext())
            {
                Principal p = (Principal)iterPrincipals.next();
                if (!(p instanceof Group))
                {
                    info.callerPrincipal = p;
                    break;
                }
            }
        }
        this.domainCache.put(principal != null ? principal : new SimplePrincipal("null"), info);
        PicketBoxLogger.LOGGER.traceInsertedCacheInfo(info.toString());
        return info.subject;
    }

    public void releaseModuleEntries(ClassLoader classLoader)
    {
        if (this.domainCache != null) {
            for (Map.Entry<Principal, DomainInfo> entry : this.domainCache.entrySet()) {
                if (((classLoader == null) && (((DomainInfo)entry.getValue()).contextClassLoader == null)) || (classLoader.equals(((DomainInfo)entry.getValue()).contextClassLoader))) {
                    flushCache((Principal)entry.getKey());
                }
            }
        }
    }

    public static class DomainInfo
            implements Serializable
    {
        private static final long serialVersionUID = 7402775370244483773L;
        protected LoginContext loginContext;
        protected Subject subject;
        protected Object credential;
        protected Principal callerPrincipal;
        protected ClassLoader contextClassLoader = null;

        @Deprecated
        public void logout()
        {
            if (this.loginContext != null) {
                try
                {
                    this.loginContext.logout();
                }
                catch (Exception e)
                {
                    PicketBoxLogger.LOGGER.traceCacheEntryLogoutFailure(e);
                }
            }
        }
    }

    public void logout(Principal principal, Subject subject)
    {
        LoginContext context = null;
        if ((this.domainCache != null) && (principal != null))
        {
            PicketBoxLogger.LOGGER.traceFlushCacheEntry(principal.getName());
            DomainInfo info = (DomainInfo)this.domainCache.get(principal);
            this.domainCache.remove(principal);
            if ((info != null) && (info.loginContext != null))
            {
                context = info.loginContext;
                subject = info.subject;
            }
        }
        if (context == null)
        {
            Object[] securityInfo = { principal, null };
            CallbackHandler theHandler = null;
            if (subject == null) {
                subject = new Subject();
            }
            try
            {
                theHandler = (CallbackHandler)this.callbackHandler.getClass().newInstance();
                this.setSecurityInfo.invoke(theHandler, securityInfo);
                context = SubjectActions.createLoginContext(this.securityDomain, subject, theHandler);
            }
            catch (Throwable e)
            {
                LoginException le = new LoginException(PicketBoxMessages.MESSAGES.unableToInitializeLoginContext(e));
                le.initCause(e);
                SubjectActions.setContextInfo("org.jboss.security.exception", le);
                return;
            }
        }
        try
        {
            context.logout();
            PicketBoxLogger.LOGGER.traceLogoutSubject(context.toString(), SubjectActions.toString(subject));
        }
        catch (LoginException le)
        {
            SubjectActions.setContextInfo("org.jboss.security.exception", le);
        }
    }
}
