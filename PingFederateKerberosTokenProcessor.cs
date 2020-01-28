public static string getEncodedSamlAssertionKerberosAuth()
        {
            System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls12;

            //Establish the Kerberos Binding for WS-Trust messaging
            KerberosWSTrustBinding kerberosBinding = new KerberosWSTrustBinding()
            {
                SecurityMode = SecurityMode.TransportWithMessageCredential,
                TrustVersion = TrustVersion.WSTrust13,
                EnableRsaProofKeys = false
            };

            string samlTokenUrl = "https://ping.domain.com/idp/sts.wst?TokenProcessorId=KerberosTokenProcessor";
            EndpointAddress ep = new EndpointAddress(new Uri(samlTokenUrl), EndpointIdentity.CreateSpnIdentity(@"HTTP/is1q.master.hmkad.hallmark.com"));
            
            WSTrustChannelFactory factory = new WSTrustChannelFactory(kerberosBinding, ep);
            factory.Credentials.Windows.ClientCredential = CredentialCache.DefaultNetworkCredentials;
            factory.TrustVersion = TrustVersion.WSTrust13;
            factory.Credentials.SupportInteractive = false;

            var rst = new RequestSecurityToken
            {
                RequestType = RequestTypes.Issue,,
                KeyType = KeyTypes.Bearer,
                AppliesTo = new EndpointReference("https://sap.domain.com:[port]/sap/bc/sec/oauth2/token")
            };

            WSTrustChannel channel = (WSTrustChannel)factory.CreateChannel();

            try
            {
                GenericXmlSecurityToken token = channel.Issue(rst) as GenericXmlSecurityToken;
                var samlAssertion = token.TokenXml.OuterXml;

                var base64Assertion = Convert.ToBase64String(Encoding.UTF8.GetBytes(samlAssertion));
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
