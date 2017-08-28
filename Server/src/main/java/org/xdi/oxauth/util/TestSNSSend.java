package org.xdi.oxauth.util;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import org.codehaus.jackson.JsonGenerationException;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.sns.AmazonSNS;
import com.amazonaws.services.sns.AmazonSNSAsync;
import com.amazonaws.services.sns.AmazonSNSAsyncClient;
import com.amazonaws.services.sns.AmazonSNSAsyncClientBuilder;
import com.amazonaws.services.sns.model.CreatePlatformEndpointRequest;
import com.amazonaws.services.sns.model.CreatePlatformEndpointResult;
import com.amazonaws.services.sns.model.MessageAttributeValue;
import com.amazonaws.services.sns.model.PublishRequest;
import com.amazonaws.services.sns.model.PublishResult;

public class TestSNSSend {

	public TestSNSSend() {
		// TODO Auto-generated constructor stub
	}

	private static Map<String, String> getData() throws JsonGenerationException, JsonMappingException, IOException {
		Map<String, String> pushRequest = new HashMap<String, String>();
		pushRequest.put("app", "https://ce-release.gluu.org/identity/authentication/authcode");
		pushRequest.put("method", "authenticate");
		pushRequest.put("req_ip", "130.180.209.30");
		pushRequest.put("created", "2017-08-28T09:57:40.665000");
		pushRequest.put("issuer", "https://ce-release.gluu.org");
		pushRequest.put("req_loc", "Ukraine%2C%20Odessa%2C%20Odesa%20%28Prymors%5C%27kyi%20district%29");
		pushRequest.put("state", "bbf58b34-dba2-4a5a-b3b8-464fc56e8649");

		ObjectMapper om = new ObjectMapper();
		String pushRequestString = om.writeValueAsString(pushRequest);

		Map<String, String> payload = new HashMap<String, String>();
		payload.put("message", pushRequestString);
		payload.put("title", "Super-Gluu");

		return payload;
	}

	public static void main(String[] args) throws JsonGenerationException, JsonMappingException, IOException, InterruptedException, ExecutionException {
	    BasicAWSCredentials credentials = new BasicAWSCredentials("AKIAI6GLLE7NZUWO57OA", "hddmu8ThOqu04/IZf9wArOTRzFbboI8hBKeEJUxp");
	    AmazonSNSAsync snsClient = AmazonSNSAsyncClientBuilder.standard().withRegion(Regions.US_WEST_2).withCredentials(new AWSStaticCredentialsProvider(credentials)).build();

		// Mobile
//		CreatePlatformEndpointRequest platformEndpointRequest = new CreatePlatformEndpointRequest();
//		platformEndpointRequest.setCustomUserData("CustomData - Useful to store endpoint specific data");
//		platformEndpointRequest.setToken("fukm21Q8tZ4:APA91bFTOULIZXqO5bwOVhZQzRaupnkt0_bcIB7RREP6ZI96-FOGbQUgflX72bIjLrwWzJZcFk8BJ4Fkhu_fA1AMYgbOgyym5ozh1CiNtkEl-o37QLpy9ylO5eJlF_OCfaMqnn8bjJ0D");
//		platformEndpointRequest.setPlatformApplicationArn("arn:aws:sns:us-west-2:989705443609:app/GCM/super_gluu_gcm");
//		
//		Future<CreatePlatformEndpointResult> platformEndpointResult = snsClient.createPlatformEndpointAsync(platformEndpointRequest);
//		System.out.println(platformEndpointResult.get().getEndpointArn());

	    PublishRequest publishRequest = new PublishRequest();
		publishRequest.setMessageStructure("json");
//		publishRequest.setMessageAttributes(messageAttributes);

		Map<String, Object> androidMessageMap = new HashMap<String, Object>();
		androidMessageMap.put("collapse_key", "single");
		androidMessageMap.put("data", getData());
		androidMessageMap.put("delay_while_idle", true);
		androidMessageMap.put("time_to_live", 30);
		androidMessageMap.put("dry_run", false);

		ObjectMapper om = new ObjectMapper();
		String message = om.writeValueAsString(androidMessageMap);

		Map<String, String> messageMap = new HashMap<String, String>();
		messageMap.put("GCM", message);
		message = om.writeValueAsString(messageMap);

		publishRequest.setTargetArn("arn:aws:sns:us-west-2:989705443609:endpoint/GCM/super_gluu_gcm/f5dfaaa7-b475-371e-a414-55c716e98921"/*platformEndpointResult.get().getEndpointArn()*/);

		// Display the message that will be sent to the endpoint/
		System.out.println("{Message Body: " + message + "}");
		StringBuilder builder = new StringBuilder();
		builder.append("{Message Attributes: ");
//		for (Map.Entry<String, MessageAttributeValue> entry : notificationAttributes
//				.entrySet()) {
//			builder.append("(\"" + entry.getKey() + "\": \""
//					+ entry.getValue().getStringValue() + "\"),");
//		}
		builder.deleteCharAt(builder.length() - 1);
		builder.append("}");
		System.out.println(builder.toString());

		publishRequest.setMessage(message);

		System.out.println(new Date());
		PublishResult publishResult = snsClient.publish(publishRequest);
		System.out.println(publishResult);
		System.out.println(new Date());

	}

}
