package com.example.frames;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;

import android.os.AsyncTask;

public class Post2 extends AsyncTask<String, Integer, Boolean> {

	@Override
	protected void onPreExecute (){
		System.out.println("About to start picture upload.");
	}
	@Override
	protected Boolean doInBackground(String... urls) {
		HttpClient httpclient = new DefaultHttpClient();
		HttpPost httppost = new HttpPost(urls[0]);

		// Request parameters and other properties.
		List<NameValuePair> params = new ArrayList<NameValuePair>(2);
		params.add(new BasicNameValuePair("picture", urls[1]));
		params.add(new BasicNameValuePair("location", urls[2]));
		try {
			httppost.setEntity(new UrlEncodedFormEntity(params, "UTF-8"));
		} catch (UnsupportedEncodingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			return false;
		}

		//Execute and get the response.
		HttpResponse response;
		try {
			response = httpclient.execute(httppost);
		} catch (ClientProtocolException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			return false;
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			return false;
		}
		HttpEntity entity = response.getEntity();

		if (entity != null) {
		    InputStream instream;
			try {
				instream = entity.getContent();
			} catch (IllegalStateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return false;
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return false;
			}
		    try {
		        // do something useful
		    } finally {
		        try {
					instream.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					return false;
				}
		    }
		}
		return true;
	}
	@Override
    protected void onPostExecute(Boolean result) {
        System.out.println("Upload success:" + result);
    }
	@Override
    protected void onProgressUpdate(Integer... progress) {
        System.out.println("Image upload progress percent: " + progress[0]);
    }

}
