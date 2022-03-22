/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.xsuaa;

import java.util.HashMap;
import java.util.Map;

import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServlet;

import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.token.Token;
import com.sap.cloud.security.xsuaa.tokenflows.TokenFlowException;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;

import static com.sap.cloud.security.xsuaa.token.TokenClaims.CLAIM_USER_NAME;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.SdkClientException;
//AWS Imports
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.internal.StaticCredentialsProvider;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.Bucket;
import com.amazonaws.services.s3.model.BucketVersioningConfiguration;
import com.amazonaws.services.s3.model.DeleteVersionRequest;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.ListObjectsV2Result;
import com.amazonaws.services.s3.model.ListVersionsRequest;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.amazonaws.services.s3.model.ResponseHeaderOverrides;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.S3ObjectInputStream;
import com.amazonaws.services.s3.model.S3ObjectSummary;
import com.amazonaws.services.s3.model.S3VersionSummary;
import com.amazonaws.services.s3.model.SetBucketVersioningConfigurationRequest;
import com.amazonaws.services.s3.model.VersionListing;
import com.nimbusds.jose.shaded.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

@RestController
public class TestController {

    private static final Logger logger = LoggerFactory.getLogger(TestController.class);

    private static final org.springframework.http.HttpStatus HttpStatus = null;

    /**
     * The injected factory for XSUAA token tokenflows.
     */
    private XsuaaTokenFlows tokenFlows;

    /**
     * A (fake) data layer showing global method security features of Spring Security
     * in combination with tokens from XSUAA.
     */
    private DataService dataService;

    @Autowired
    public TestController(XsuaaTokenFlows tokenFlows, DataService dataService) {
        this.tokenFlows = tokenFlows;
        this.dataService = dataService;
    }

    

    @GetMapping("/health")
    public String sayHello() { return "I'm alright"; }


    /**
     * Returns the detailed information of the XSUAA JWT token.
     * Uses a Token retrieved from the security context of Spring Security.
     *
     * @param token the XSUAA token from the request injected by Spring Security.
     * @return the requested address.
     * @throws Exception in case of an internal error.
     */
    
    @GetMapping("/v1/ListObjects")
    public ListObjectsV2Result ListObjects() {

        //String bucket_name = "myawsbucket-alag";
        // if (args.length < 1) {
        // System.out.println(USAGE);
        // System.exit(1);
        // }

        // System.out.format("Objects in S3 bucket %s:\n", bucket_name);

        // AWSCredentialsProvider aws = new AWSCredentialsProvider();
        // final AmazonS3 s3 =
        // AmazonS3ClientBuilder.standard().withRegion("us-east-2").build();
        // AWSCredentialsProvider sd = new AWSCredentialsProvider(ds);

        BasicAWSCredentials aws = new BasicAWSCredentials(AWSConfig.access_key,
        AWSConfig.access_secret);
        StaticCredentialsProvider scp = new StaticCredentialsProvider(aws);
        // final AmazonS3 s3 =
        // AmazonS3ClientBuilder.standard().withRegion("us-east-2").withCredentials(sd).build();
        final AmazonS3 s3 = AmazonS3ClientBuilder.standard().withRegion(AWSConfig.region).withCredentials(scp).build();
        // AmazonS3Client s4 = AmazonS3Client.builder().creden
        // Bucket bucket = s3.createBucket("check");

        System.out.format("Objects in S3 bucket %s:\n", AWSConfig.bucket_name);
        ListObjectsV2Result result = s3.listObjectsV2(AWSConfig.bucket_name);
        List<S3ObjectSummary> objects = result.getObjectSummaries();
        for (S3ObjectSummary os : objects) {
            System.out.println("* " + os.getKey());
        }
       return result;
    }

    @GetMapping("/v1/ListVersionsRequest")
    public List<S3VersionSummary> ListVersionsRequest() {
        //return "Goodbye from Spring Boot";
    
        BasicAWSCredentials aws = new BasicAWSCredentials(AWSConfig.access_key,
        AWSConfig.access_secret);
        StaticCredentialsProvider scp = new StaticCredentialsProvider(aws);
        // final AmazonS3 s3 =
        // AmazonS3ClientBuilder.standard().withRegion("us-east-2").withCredentials(sd).build();
        final AmazonS3 s3 = AmazonS3ClientBuilder.standard().withRegion(AWSConfig.region).withCredentials(scp).build();
        
        // Retrieve the list of versions. If the bucket contains more versions
        // than the specified maximum number of results, Amazon S3 returns
        // one page of results per request.
    ListVersionsRequest request = new ListVersionsRequest().withBucketName(AWSConfig.bucket_name).withMaxResults(200);
    VersionListing versionListing = s3.listVersions(request);
    int numVersions = 0, numPages = 0;
    
    List<S3VersionSummary> objectSummary = versionListing.getVersionSummaries();
    
    while (true) {
    numPages++;
    for (S3VersionSummary s3v : objectSummary) {
    System.out.printf("Retrieved object %s, version %s\n", s3v.getKey(), s3v.getVersionId());
    numVersions++;
    }
    // Check whether there are more pages of versions to retrieve. If there are, retrieve them. Otherwise, exit the loop.
    if (versionListing.isTruncated()) {
    versionListing = s3.listNextBatchOfVersions(versionListing);
    } else {
    break;
    }
}
           return objectSummary;
        }

        @GetMapping("/v1/BucketVersionHandler")
        public String BucketVersionHandler() {
    
            BasicAWSCredentials aws = new BasicAWSCredentials(AWSConfig.access_key,
        AWSConfig.access_secret);
        StaticCredentialsProvider scp = new StaticCredentialsProvider(aws);
        // final AmazonS3 s3 =
        // AmazonS3ClientBuilder.standard().withRegion("us-east-2").withCredentials(sd).build();
        final AmazonS3 s3 = AmazonS3ClientBuilder.standard().withRegion(AWSConfig.region).withCredentials(scp).build();
            
            // Enable versioning on the bucket.
            BucketVersioningConfiguration configuration = new BucketVersioningConfiguration().withStatus("Enabled");            
            SetBucketVersioningConfigurationRequest setBucketVersioningConfigurationRequest = new SetBucketVersioningConfigurationRequest(AWSConfig.bucket_name,configuration);
            s3.setBucketVersioningConfiguration(setBucketVersioningConfigurationRequest);
            return "Bucket Versioning Modified";

        }

        @GetMapping("/v1/BucketVersionStatus")
        public BucketVersioningConfiguration BucketVersionStatus() {
    
            BasicAWSCredentials aws = new BasicAWSCredentials(AWSConfig.access_key,
        AWSConfig.access_secret);
        StaticCredentialsProvider scp = new StaticCredentialsProvider(aws);
        // final AmazonS3 s3 =
        // AmazonS3ClientBuilder.standard().withRegion("us-east-2").withCredentials(sd).build();
        final AmazonS3 s3 = AmazonS3ClientBuilder.standard().withRegion(AWSConfig.region).withCredentials(scp).build();
    
            // Get bucket versioning configuration information.
            BucketVersioningConfiguration conf = s3.getBucketVersioningConfiguration(AWSConfig.bucket_name);
            System.out.println("bucket versioning configuration status:    " + conf.getStatus());
            return conf ;
        }
        
        @GetMapping("/v1/GetObject")
        public String GetObject() {

            String object_key = "customer.tbl";
    
            BasicAWSCredentials aws = new BasicAWSCredentials(AWSConfig.access_key,
        AWSConfig.access_secret);
        StaticCredentialsProvider scp = new StaticCredentialsProvider(aws);
        // final AmazonS3 s3 =
        // AmazonS3ClientBuilder.standard().withRegion("us-east-2").withCredentials(sd).build();
        final AmazonS3 s3 = AmazonS3ClientBuilder.standard().withRegion(AWSConfig.region).withCredentials(scp).build();
    

    System.out.format("Downloading object %s from S3 bucket: %s\n", object_key,
    AWSConfig.bucket_name);
    try {
        s3.getObject(new GetObjectRequest(AWSConfig.bucket_name, object_key));
    } catch (AmazonServiceException e) {
        System.err.println(e.getErrorMessage());
        System.exit(1);
    }
    System.out.println("Done!");
            return "Downloaded the Object" ;
        }

        @GetMapping("/v1/DeleteObject")
        public String DeleteObject() {
		
            String object_key = "nation.tbl";
    
            BasicAWSCredentials aws = new BasicAWSCredentials(AWSConfig.access_key,
        AWSConfig.access_secret);
        StaticCredentialsProvider scp = new StaticCredentialsProvider(aws);
        // final AmazonS3 s3 =
        // AmazonS3ClientBuilder.standard().withRegion("us-east-2").withCredentials(sd).build();
        final AmazonS3 s3 = AmazonS3ClientBuilder.standard().withRegion(AWSConfig.region).withCredentials(scp).build();
    

    System.out.format("Deleting object %s from S3 bucket: %s\n", object_key,
    AWSConfig.bucket_name);
    try {
        s3.deleteObject(AWSConfig.bucket_name, object_key);
    } catch (AmazonServiceException e) {
        System.err.println(e.getErrorMessage());
        System.exit(1);
    }
    System.out.println("Done!");
            return "Deleted the Object" ;
        }

        @GetMapping("/v1/DeleteObjectVersion")
        public String DeleteObjectVersion() {
		
            String object_key = "nation.tbl";
            String version_key = "SlZA0maq1ujOYQW1frQuJkyAvCWt5_1e";
    
            BasicAWSCredentials aws = new BasicAWSCredentials(AWSConfig.access_key,
        AWSConfig.access_secret);
        StaticCredentialsProvider scp = new StaticCredentialsProvider(aws);
        // final AmazonS3 s3 =
        // AmazonS3ClientBuilder.standard().withRegion("us-east-2").withCredentials(sd).build();
        final AmazonS3 s3 = AmazonS3ClientBuilder.standard().withRegion(AWSConfig.region).withCredentials(scp).build();
    

    System.out.format("Deleting object %s from S3 bucket: %s\n", object_key,
    AWSConfig.bucket_name);
    try {
        s3.deleteVersion(new DeleteVersionRequest(AWSConfig.bucket_name, object_key, version_key));
    } catch (AmazonServiceException e) {
        System.err.println(e.getErrorMessage());
        System.exit(1);
    }
    System.out.println("Done!");
            return "Deleted the Object Version" ;
        }
    // PUT object
        
    @GetMapping("/v1/PutObjects")
        public String PutObjects() {

            //Time Code
            DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");  
            LocalDateTime now = LocalDateTime.now();  
            System.out.println(dtf.format(now));  
		
            String file_content = "Sample File Upload  " + dtf.format(now);
            String file_name = "PutFileNewMethod.txt"; 
      
            BasicAWSCredentials aws = new BasicAWSCredentials(AWSConfig.access_key,
        AWSConfig.access_secret);
        StaticCredentialsProvider scp = new StaticCredentialsProvider(aws);
        // final AmazonS3 s3 =
        // AmazonS3ClientBuilder.standard().withRegion("us-east-2").withCredentials(sd).build();
        final AmazonS3 s3 = AmazonS3ClientBuilder.standard().withRegion(AWSConfig.region).withCredentials(scp).build();
    
        System.out.format("Uploading %s to S3 bucket %s...\n", file_name, AWSConfig.bucket_name);
        try {
            s3.putObject(AWSConfig.bucket_name, file_name, file_content);
        } catch (AmazonServiceException e) {
            System.err.println(e.getErrorMessage());
            System.exit(1);
        }
        System.out.println("Done!");
        return "Uploaded Successfully!";
    }    

    //GET OBJECTS
    @GetMapping("/v1/GetObjects")
    public JSONObject GetObjects() {


        String file_name = "PutFileNewMethod.txt"; 
  
        BasicAWSCredentials aws = new BasicAWSCredentials(AWSConfig.access_key,
        AWSConfig.access_secret);
        StaticCredentialsProvider scp = new StaticCredentialsProvider(aws);
        // final AmazonS3 s3 =
        // AmazonS3ClientBuilder.standard().withRegion("us-east-2").withCredentials(sd).build();
        final AmazonS3 s3 = AmazonS3ClientBuilder.standard().withRegion(AWSConfig.region).withCredentials(scp).build();
        
        S3Object o = s3.getObject(AWSConfig.bucket_name, file_name);
		BufferedReader reader = new BufferedReader(new InputStreamReader(o.getObjectContent()));
		StringBuilder sbuilder = new StringBuilder();
		String line;
		try {
            while ((line = reader.readLine()) != null) {
            	sbuilder.append(line);
            }
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
		
		JSONObject result = new JSONObject();
		result.put("file_content", sbuilder.toString());
		result.put("file_meta",o.getObjectMetadata().getRawMetadata());
		
		return result;
} 
}
