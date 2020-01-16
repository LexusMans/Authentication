using System;
using System.Web;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.ServiceModel.Security;
using System.ServiceModel;
using System.Web.Script.Serialization;
using System.IdentityModel.Tokens;
using System.IdentityModel.Protocols.WSTrust;
using Thinktecture.IdentityModel.WSTrust;
using System.Windows.Forms;
using System.DirectoryServices.ActiveDirectory;

public static string getEncodedSamlAssertionKerberosAuth()
{
    System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls12;
   
   var domain = Domain.GetCurrentDomain().ToString();
   
    //Establish the Kerberos Binding for WS-Trust messaging
    KerberosWSTrustBinding kerberosBinding = new KerberosWSTrustBinding()
    {
        SecurityMode = SecurityMode.TransportWithMessageCredential,
        TrustVersion = TrustVersion.WSTrust13,
        EnableRsaProofKeys = false
    };

    WSTrustChannelFactory factory = new WSTrustChannelFactory(kerberosBinding, "https://ping.domain.com/idp/sts.wst?TokenProcessorId=KerberosTokenProcessor");
    factory.Credentials.Windows.ClientCredential.UserName = "my username";
    factory.Credentials.Windows.ClientCredential.Password = "my password";
    factory.Credentials.Windows.ClientCredential.Domain = domain;
    factory.Credentials.SupportInteractive = false;

    var rst = new RequestSecurityToken
    {
        RequestType = RequestTypes.Issue,
        AppliesTo = new EndpointReference("https://sap.domain.com:[port]/sap/bc/sec/oauth2/token"),
        KeyType = KeyTypes.Bearer,
        //TokenType = "urn:oasis:names:tc:SAML:2.0:assertion",
    };

    WSTrustChannel channel = (WSTrustChannel)factory.CreateChannel();

    try
    {
        GenericXmlSecurityToken token = channel.Issue(rst) as GenericXmlSecurityToken;

        var samlAssertionXml = token.TokenXml.OuterXml;

        var base64Assertion = Convert.ToBase64String(Encoding.UTF8.GetBytes(samlAssertionXml));
        string encodedSamlAssertion = HttpUtility.HtmlEncode(base64Assertion);

        return encodedSamlAssertion;
    }
    catch (Exception ex)
    {
        Console.WriteLine("Exception: " + ex.Message);
        Console.WriteLine("InnerException: " + ex.InnerException);
        throw ex;
    }
    finally
    {
        factory.Close();
    }
}