using System;
using System.IdentityModel.Tokens;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace saml_samples
{
	class Program
	{
		static void Main( string[] args )
		{
			var response =
			@"<saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID = ""_{0}"" Version=""2.0"" IssueInstant=""2015-01-01T00:00:00Z"">
                <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                {1}
            </saml2p:Response>";

			var assertion = new Saml2Assertion( new Saml2NameIdentifier( "https://idp.example.com" ) );
			assertion.Subject = new Saml2Subject( new Saml2NameIdentifier( "SomeUser" ) );
			assertion.Subject.SubjectConfirmations.Add( new Saml2SubjectConfirmation( new Uri( "urn:oasis:names:tc:SAML:2.0:cm:bearer" ) ) );

			assertion.Conditions = new Saml2Conditions {
				NotOnOrAfter = new DateTime( 2100, 1, 1 ) 
			};

			assertion.Statements.Add( new Saml2AttributeStatement( new Saml2Attribute( "FooID", "12345" ) ) );

			var signingCert = new X509Certificate2( @"C:\Dev\STS.pfx", "somepassword" );
			var assertionHelper = new AssertionHelper( signingCert );
			var signedAssertion = assertionHelper.SignAssertion( assertion );
			var fullResponse = string.Format( response, Guid.NewGuid().ToString(), signedAssertion );

			File.WriteAllText( @"C:\dev\samlResponse.xml", fullResponse );
		}
	}
}