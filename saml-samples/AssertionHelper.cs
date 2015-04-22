using System;
using System.IdentityModel.Tokens;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace saml_samples
{
	class AssertionHelper
	{
		public AssertionHelper( X509Certificate2 signingCert ) 
			: this(signingCert, null)
		{
		}

		public AssertionHelper( X509Certificate2 signingCert, X509Certificate2 encryptionCert )
		{
			SigningCredentials = new X509SigningCredentials( signingCert, SecurityAlgorithms.RsaSha1Signature, SecurityAlgorithms.Sha1Digest );
			if ( encryptionCert != null )
			{
				EncryptionCredentials = new X509EncryptingCredentials( encryptionCert );
			}
		}

		public string SignAssertion( Saml2Assertion assertion )
		{
			string signedAssertion = String.Empty;
			var token = new Saml2SecurityToken( assertion );
			var handler = new Saml2SecurityTokenHandler();
			assertion.SigningCredentials = SigningCredentials;
			assertion.EncryptingCredentials = EncryptionCredentials;
			using ( var stringWriter = new StringWriter() )
			{
				using ( var xmlWriter = XmlWriter.Create( stringWriter,
				new XmlWriterSettings { OmitXmlDeclaration = true } ) )
				{
					handler.WriteToken( xmlWriter, token );
				}
				signedAssertion = stringWriter.ToString();
			}
			return signedAssertion;
		}

		private readonly SigningCredentials SigningCredentials;
		private readonly EncryptingCredentials EncryptionCredentials;
	}
}