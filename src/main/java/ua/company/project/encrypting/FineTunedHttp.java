package ua.company.project.encrypting;

public class FineTunedHttp {

	
	 private String sendRequestFullTunned(HttpRequestBase method) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
	        
	        /// create trust all socket factory
	        TrustStrategy tStrategy = (X509Certificate[] xcs, String string) -> {return true;};        
	        SSLContext context = SSLContexts.custom().loadTrustMaterial(null, tStrategy).build();
	        SSLConnectionSocketFactory factory = new SSLConnectionSocketFactory(context,
	                new String[]{"TLSv1", "TLSv1.1", "TLSv1.2", "SSLv3"},
	                null,
	                NoopHostnameVerifier.INSTANCE);
	        /// create registry
	        RegistryBuilder<ConnectionSocketFactory> socketFactoryRegistryBuilder = RegistryBuilder.<ConnectionSocketFactory>create()
	                .register("http", PlainConnectionSocketFactory.INSTANCE)
	                .register("https", factory);
	        
	        
	        //// create polling connection manager
	        PoolingHttpClientConnectionManager manager = new PoolingHttpClientConnectionManager(socketFactoryRegistryBuilder.build());
	        manager.setDefaultMaxPerRoute(3);
	        manager.setMaxTotal(5);
	        
	        //// crate basic auth
	         CredentialsProvider provider =  new BasicCredentialsProvider();
	         UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("", "");
	         provider.setCredentials(AuthScope.ANY, credentials);
	         
	         /// create request config
	         RequestConfig.Builder requestBuilder = RequestConfig.custom()                     
	                        .setSocketTimeout(60 * 1000)
	                        .setConnectTimeout(180 * 1000)
	                        .setConnectionRequestTimeout(60 * 1000);
	        // add proxy
	        HttpHost proxy = new HttpHost("proxyHost", 8090);
	        DefaultProxyRoutePlanner routePlaner = new DefaultProxyRoutePlanner(proxy);
	        
	        
	        
	        /**
	         * or
	        HttpHost proxy = new HttpHost("proxyHost", 8090);
	        DefaultProxyRoutePlanner routePlaner = new DefaultProxyRoutePlanner(proxy);
	         * /// add proxy  basic auth
	        // use client.execute(method, clientContext) if have proxy auth
	        CredentialsProvider proxyAuth =  new BasicCredentialsProvider();
	        UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("proxyName", "proxyPassword");
	        proxyAuth.setCredentials(new AuthScope("proxyHost", 8080), credentials);
	        
	        AuthCache authCache = new BasicAuthCache();
	        BasicScheme basicAuth = new BasicScheme();
	        authCache.put(proxy, basicAuth);
	        
	        HttpClientContext clientContext = HttpClientContext.create();
	        clientContext.setAuthCache(authCache);
	        clientContext.setCredentialsProvider(proxyAuth);
	         
	        * // use client.execute(method, clientContext) if have proxy auth
	        */
	        
	        try(CloseableHttpClient client = HttpClients.custom()
	                .setConnectionManager(manager)
	                .setDefaultRequestConfig(requestBuilder.build())
	                .setProxy(proxy)
	                .setDefaultCredentialsProvider(provider)
	                .setRoutePlanner(routePlaner)
	                .build();

	                CloseableHttpResponse responce = client.execute(method)){
	            
	            
	            
	            int statusCode = responce.getStatusLine().getStatusCode();
	            System.out.println(statusCode);

	            String text = IOUtils.toString(responce.getEntity().getContent(), StandardCharsets.UTF_8);
	            System.out.println(text);
	            
	            System.out.println(Arrays.toString(responce.getAllHeaders())); 
	           
	            
	            
	            return text;
	        } catch (Exception ex){
	            ex.printStackTrace();
	            return null;
	        }
	    }
}
