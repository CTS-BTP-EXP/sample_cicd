package sample.spring.xsuaa;

import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

/**
 * This is AWS Credentials Configuration class
 *
 */

//@Profile("cloud-aws")
//@Configuration
//@ConfigurationProperties(prefix = "vcap.services.objectstore-service.credentials")
public class AWSConfig {
	
	/* For Local Usage
    public static String access_key = "Your Aws Access Key"; ;
	public static String bucket_name = "Your Aws Bucket Name";
	public static String access_secret = "Your Aws Secret Key";
    public static String region = "Your Aws Region";*/



    public static JSONObject vcap = new JSONObject(System.getenv("VCAP_SERVICES"));
	public static JSONObject s3_credentials = vcap.getJSONArray("objectstore-service").getJSONObject(0).getJSONObject("credentials");
		
		public static String access_key = s3_credentials.getString("access_key_id");
		public static String access_secret = s3_credentials.getString("secret_access_key");
		public static String region = s3_credentials.getString("region");
        public static String bucket_name = s3_credentials.getString("bucket");

    

	
	
	
}



