package ujr.saml.generator;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.xml.namespace.QName;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Condition;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.OneTimeUse;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.impl.AssertionMarshaller;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.IssuerMarshaller;
import org.opensaml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml2.core.impl.ResponseMarshaller;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.SubjectMarshaller;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.impl.SignatureMarshaller;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

/**
 * Hello world!
 *
 */
public class SAMLMain {
	public static void main(String[] args) throws Exception {
		DefaultBootstrap.bootstrap();
		// SecureRandomIdentifierGenerator generator = new
		// SecureRandomIdentifierGenerator();

		// My Private Key / Digital Certified
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(new FileInputStream("c:/Users/uraa/ualterkeystore.jks"), "ualter".toCharArray());
		KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry("client", new KeyStore.PasswordProtection("ualter".toCharArray()));
		X509Certificate certificate = (X509Certificate) pkEntry.getCertificate();
		BasicX509Credential credential = new BasicX509Credential();
		credential.setEntityCertificate(certificate);
		PrivateKey pk = pkEntry.getPrivateKey();
		credential.setPrivateKey(pk);
		Credential signingCredential = credential;

		// Generate Digitall Signature
		Signature signature = (Signature) Configuration.getBuilderFactory().getBuilder(Signature.DEFAULT_ELEMENT_NAME).buildObject(Signature.DEFAULT_ELEMENT_NAME);
		signature.setSigningCredential(signingCredential);
		SecurityConfiguration secConfig = Configuration.getGlobalSecurityConfiguration();
		String keyInfoGeneratorProfile = "XMLSignature";
		SecurityHelper.prepareSignatureParams(signature, signingCredential, secConfig, null);
		SignatureMarshaller m = new SignatureMarshaller();
		System.out.println("************* Digital Signature with my Private Key *** ");
		System.out.println(XMLHelper.nodeToString(m.marshall(signature)));

		// SAML Assertions
		SAMLInput input = new SAMLInput();
		String strIssuer = "yomismo";
		input.setStrIssuer(strIssuer);
		input.setStrNameID("ualter");

		input.setStrNameQualifier("urlqualquiera");
		input.setSessionId("abcdedf1234567");

		Map customAttributes = new HashMap();
		customAttributes.put("Custom_data", "custom_data_value");
		customAttributes.put("Partner_Client_ID", "Partner_Client_Value");
		input.setAttributes(customAttributes);

		String strUrl = "strUrl";
		String strSubjectConfUrl = "strSubjectConfUrl";
		String strUrlSSO = "strUrlSSO";
		// Create the NameIdentifier
		SAMLObjectBuilder nameIdBuilder = (SAMLObjectBuilder) getSAMLBuilder().getBuilder(NameID.DEFAULT_ELEMENT_NAME);
		NameID nameId = (NameID) nameIdBuilder.buildObject();
		nameId.setValue(input.getStrNameID());
		nameId.setNameQualifier(input.getStrNameQualifier());
		nameId.setFormat(NameID.UNSPECIFIED);

		// Create the SubjectConfirmation
		SAMLObjectBuilder confirmationMethodBuilder = (SAMLObjectBuilder) getSAMLBuilder().getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
		SubjectConfirmationData confirmationMethod = (SubjectConfirmationData) confirmationMethodBuilder.buildObject();
		DateTime now = new DateTime();
		confirmationMethod.setNotBefore(now);
		confirmationMethod.setNotOnOrAfter(now.plusMinutes(2));
		confirmationMethod.setRecipient(strSubjectConfUrl);
		SAMLObjectBuilder subjectConfirmationBuilder = (SAMLObjectBuilder) getSAMLBuilder().getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
		SubjectConfirmation subjectConfirmation = (SubjectConfirmation) subjectConfirmationBuilder.buildObject();
		subjectConfirmation.setSubjectConfirmationData(confirmationMethod);

		// Create the Subject
		SAMLObjectBuilder subjectBuilder = (SAMLObjectBuilder) getSAMLBuilder().getBuilder(Subject.DEFAULT_ELEMENT_NAME);
		Subject subject = (Subject) subjectBuilder.buildObject();
		subject.setNameID(nameId);
		subject.getSubjectConfirmations().add(subjectConfirmation);

		SAMLObjectBuilder audienceBuilder = (SAMLObjectBuilder) getSAMLBuilder().getBuilder(Audience.DEFAULT_ELEMENT_NAME);
		Audience audience = (Audience) audienceBuilder.buildObject();
		audience.setAudienceURI(strUrlSSO);

		SAMLObjectBuilder audienceRestrictionBuilder = (SAMLObjectBuilder) getSAMLBuilder().getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME);
		AudienceRestriction audienceRestriction = (AudienceRestriction) audienceRestrictionBuilder.buildObject();
		List<Audience> audiences = audienceRestriction.getAudiences();
		audiences.add(audience);

		SAMLObjectBuilder conditionsBuilder = (SAMLObjectBuilder) getSAMLBuilder().getBuilder(Conditions.DEFAULT_ELEMENT_NAME);
		Conditions conditions = (Conditions) conditionsBuilder.buildObject();

		List<AudienceRestriction> audienceRestrictions = conditions.getAudienceRestrictions();
		audienceRestrictions.add(audienceRestriction);

		// Create Authentication Statement
		SAMLObjectBuilder authStatementBuilder = (SAMLObjectBuilder) getSAMLBuilder().getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
		AuthnStatement authnStatement = (AuthnStatement) authStatementBuilder.buildObject();
		// authnStatement.setSubject(subject);
		// authnStatement.setAuthenticationMethod(strAuthMethod);
		DateTime now2 = new DateTime();
		authnStatement.setAuthnInstant(now2);
		authnStatement.setSessionIndex(input.getSessionId());
		authnStatement.setSessionNotOnOrAfter(now2.plus(input.getMaxSessionTimeoutInMinutes()));

		SAMLObjectBuilder authContextBuilder = (SAMLObjectBuilder) getSAMLBuilder().getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME);
		AuthnContext authnContext = (AuthnContext) authContextBuilder.buildObject();

		SAMLObjectBuilder authContextClassRefBuilder = (SAMLObjectBuilder) getSAMLBuilder().getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
		AuthnContextClassRef authnContextClassRef = (AuthnContextClassRef) authContextClassRefBuilder.buildObject();
		authnContextClassRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:Password");

		authnContext.setAuthnContextClassRef(authnContextClassRef);
		authnStatement.setAuthnContext(authnContext);

		// Builder Attributes
		SAMLObjectBuilder attrStatementBuilder = (SAMLObjectBuilder) getSAMLBuilder().getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
		AttributeStatement attrStatement = (AttributeStatement) attrStatementBuilder.buildObject();

		Map attributes = input.getAttributes();
		if (attributes != null) {
			Iterator keySet = attributes.keySet().iterator();
			while (keySet.hasNext()) {
				String key = keySet.next().toString();
				String val = attributes.get(key).toString();
				Attribute attrFirstName = buildStringAttribute(key, val, getSAMLBuilder());
				attrStatement.getAttributes().add(attrFirstName);
			}
		}

		// Create the do-not-cache condition
		SAMLObjectBuilder doNotCacheConditionBuilder = (SAMLObjectBuilder) getSAMLBuilder().getBuilder(OneTimeUse.DEFAULT_ELEMENT_NAME);
		Condition condition = (Condition) doNotCacheConditionBuilder.buildObject();

		// Create Issuer
		SAMLObjectBuilder issuerBuilder_ = (SAMLObjectBuilder) getSAMLBuilder().getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		Issuer issuer = (Issuer) issuerBuilder_.buildObject();
		issuer.setValue(input.getStrIssuer());

		// Create the assertion
		SAMLObjectBuilder assertionBuilder = (SAMLObjectBuilder) getSAMLBuilder().getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
		Assertion assertion = (Assertion) assertionBuilder.buildObject();
		assertion.setIssuer(issuer);
		assertion.setIssueInstant(now);
		assertion.setVersion(SAMLVersion.VERSION_20);
		assertion.setSubject(subject); 

		assertion.getAuthnStatements().add(authnStatement);
		assertion.getAttributeStatements().add(attrStatement);
		assertion.setConditions(conditions);

		// assertion = SamlAssertion.buildDefaultAssertion(input, strUrlSSO,
		// strUrl, strSubjectConfUrl);
		AssertionMarshaller marshaller = new AssertionMarshaller();
		Element plaintextElement = marshaller.marshall(assertion);
		String originalAssertionString = XMLHelper.nodeToString(plaintextElement);
		System.out.println("\n\n************* SAML Assertions *** ");
		System.out.println(originalAssertionString);

		
		// Response
		ResponseBuilder responseBuilder = new ResponseBuilder();
		Response resp = responseBuilder.buildObject();
		
		// Status
		StatusBuilder statusBuilder = new StatusBuilder();   
	    Status status = statusBuilder.buildObject();
	    resp.setStatus(status);
	    // Destination
	    resp.setDestination(strUrl);    
	    resp.getAssertions().add(assertion);
	    // Issuer
	    IssuerBuilder issuerBuilder = new IssuerBuilder();
	    Issuer iss = issuerBuilder.buildObject();
	    iss.setValue(strIssuer);
	    resp.setIssuer(iss);
	    resp.setSignature(signature);
	    
	    Configuration.getMarshallerFactory().getMarshaller(resp).marshall(resp);
	    Signer.signObject(signature);
	    ResponseMarshaller responseMarshaller = new ResponseMarshaller();
	    Element plain = responseMarshaller.marshall(resp);
	    String samlResponse = XMLHelper.nodeToString(plain);
	    System.out.println("\n\n************* SAML Response *** ");
		System.out.println(samlResponse);
	    
		System.out.println("\n\n=========== END ===========\n\n");
	}

	private static XMLObjectBuilderFactory builderFactory;

	public static XMLObjectBuilderFactory getSAMLBuilder() throws ConfigurationException {
		if (builderFactory == null) {
			// OpenSAML 2.3
			DefaultBootstrap.bootstrap();
			builderFactory = Configuration.getBuilderFactory();
		}
		return builderFactory;
	}

	public static Attribute buildStringAttribute(String name, String value, XMLObjectBuilderFactory builderFactory) throws ConfigurationException {
		SAMLObjectBuilder attrBuilder = (SAMLObjectBuilder) getSAMLBuilder().getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
		Attribute attrFirstName = (Attribute) attrBuilder.buildObject();
		attrFirstName.setName(name);

		// Set custom Attributes
		XMLObjectBuilder stringBuilder = getSAMLBuilder().getBuilder(XSString.TYPE_NAME);
		XSString attrValueFirstName = (XSString) stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
		attrValueFirstName.setValue(value);

		attrFirstName.getAttributeValues().add(attrValueFirstName);
		return attrFirstName;
	}

	private static void testSAML() throws MarshallingException {
		Issuer issuer = create(Issuer.class, Issuer.DEFAULT_ELEMENT_NAME);
		issuer.setValue("urlQualquiera");

		String username = "USERNAME";
		NameID nameID = create(NameID.class, NameID.DEFAULT_ELEMENT_NAME);
		nameID.setValue(username);
		Subject subject = create(Subject.class, Subject.DEFAULT_ELEMENT_NAME);
		subject.setNameID(nameID);
		SubjectConfirmation confirmation = create(SubjectConfirmation.class, SubjectConfirmation.DEFAULT_ELEMENT_NAME);
		confirmation.setMethod("conf");
		subject.getSubjectConfirmations().add(confirmation);

		IssuerMarshaller mIssuer = new IssuerMarshaller();
		System.out.println(XMLHelper.nodeToString(mIssuer.marshall(issuer)));

		SubjectMarshaller mSubject = new SubjectMarshaller();
		System.out.println(XMLHelper.nodeToString(mSubject.marshall(subject)));
	}

	@SuppressWarnings("unchecked")
	public static <T> T create(Class<T> cls, QName qname) {
		return (T) ((XMLObjectBuilder) Configuration.getBuilderFactory().getBuilder(qname)).buildObject(qname);
	}
}
