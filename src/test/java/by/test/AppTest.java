package by.test;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.proc.BadJWSException;
import com.nimbusds.jose.util.ByteUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import java.text.ParseException;
import java.util.Date;

/**
 * Unit test for simple App.
 */
public class AppTest extends TestCase {
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public AppTest( String testName )
    {
        super( testName );
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
        return new TestSuite( AppTest.class );
    }

    public void testVerify_secretTooShort() throws Exception {

        Secret clientSecret = new Secret(ByteUtils.byteLength(256));

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");
        Date now = new Date();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                  .issuer(iss.getValue())
                  .subject("alice")
                  .audience(clientID.getValue())
                  .expirationTime(new Date(now.getTime() + 10*60*1000L))
                  .issueTime(now)
                  .build();

        SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
        idToken.sign(new MACSigner(clientSecret.getValueBytes()));

        // Too short secret
        IDTokenValidator idTokenValidator = new IDTokenValidator(iss, clientID, JWSAlgorithm.HS256, new Secret(16));

        try {
            idTokenValidator.validate(idToken, null);
            fail();
        } catch (KeyLengthException e) {
            assertEquals("The secret length must be at least 256 bits", e.getMessage());
        }
    }

    public void testVerifyBadHmac() throws Exception {

        Secret clientSecret = new Secret(ByteUtils.byteLength(256));

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");
        Date now = new Date();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                  .issuer(iss.getValue())
                  .subject("alice")
                  .audience(clientID.getValue())
                  .expirationTime(new Date(now.getTime() + 10*60*1000L))
                  .issueTime(now)
                  .build();

        SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
        idToken.sign(new MACSigner(new Secret(ByteUtils.byteLength(256)).getValueBytes()));

        IDTokenValidator idTokenValidator = new IDTokenValidator(iss, clientID, JWSAlgorithm.HS256, clientSecret);

        try {
            idTokenValidator.validate(idToken, null);
            fail();
        } catch (BadJWSException e) {
            assertEquals("Signed JWT rejected: Invalid signature", e.getMessage());
        }
    }


}
