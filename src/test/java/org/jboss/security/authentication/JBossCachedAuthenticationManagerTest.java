package org.jboss.security.authentication;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import java.security.Principal;
import java.util.concurrent.TimeoutException;
import javax.security.auth.callback.CallbackHandler;

import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;


/**
 * Created by JStobbs on 15/06/2017.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest(SubjectActions.class)
@PowerMockIgnore({"javax.security.*", "java.security.*" , "java.lang.*"})
public class JBossCachedAuthenticationManagerTest
{

    @Test
    public void RuntimeException_Caught_And_Rethrown_AS_LoginException_Test()
    {
        // A runtime exception is caused in the second half of the defaultLogin method, which is caught and rethrown wrapped by LoginException.
        // This proves that the correct version of the class is being used and checks that the fix is working as expected.

        JBossCachedAuthenticationManager jBossCachedAuthenticationManager = new JBossCachedAuthenticationManager();

        try
        {
            Principal principal = mock(Principal.class);
            Object object = mock(Object.class);
            javax.security.auth.callback.CallbackHandler handler = mock(CallbackHandler.class);
            String securityDomain = "";
            Subject subject = new Subject();
            PowerMockito.mockStatic(SubjectActions.class);
            Mockito.when(SubjectActions.createLoginContext(securityDomain,subject,handler)).thenReturn(null);
            PowerMockito.doThrow(new RuntimeException("WM384 Test Error")).when(SubjectActions.class);
            SubjectActions.createLoginContext(securityDomain, subject, handler);
            jBossCachedAuthenticationManager.defaultLogin(principal,object);
        }
        catch (LoginException e)
        {
            return;
        }

        fail();
    }

    @Test
    public void TimeoutException_Not_Caught_And_Rethrown_As_LoginException_Test()
    {
        // A timeout exception is caused in the second half of the defaultLogin method, this is not caught and rethrown wrapped by LoginException.

        JBossCachedAuthenticationManager jBossCachedAuthenticationManager = new JBossCachedAuthenticationManager();

        try
        {
            Principal principal = mock(Principal.class);
            Object object = mock(Object.class);
            javax.security.auth.callback.CallbackHandler handler = mock(CallbackHandler.class);
            String securityDomain = "";
            Subject subject = new Subject();
            PowerMockito.mockStatic(SubjectActions.class);
            Mockito.when(SubjectActions.createLoginContext(securityDomain,subject,handler)).thenReturn(null);
            PowerMockito.doThrow(new TimeoutException("WM384_2 Test Error")).when(SubjectActions.class);
            SubjectActions.createLoginContext(securityDomain, subject, handler);
            jBossCachedAuthenticationManager.defaultLogin(principal,object);
        }
        catch (LoginException e)
        {
            fail();
        }
        catch (Exception e)
        {
            return;
        }
    }
}
