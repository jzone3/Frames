package com.example.frames;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.URLConnection;
import java.net.URL;

import android.os.AsyncTask;

public class Post extends AsyncTask<String, Integer, Boolean> {

	@Override
	protected void onPreExecute (){
		System.out.println("About to start picture upload.");
	}
	@Override
	protected Boolean doInBackground(String... urls) {
		URL url = null;
        try {
        	url = new URL(urls[0]);
        } catch (Exception e) {
        	// TODO Auto-generated catch block
        	e.printStackTrace();
        	
        	return false;
        }
		
		URLConnection conn = null;
		try {
			conn = url.openConnection();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("should print");
			return false;
		}
		
        conn.setDoOutput(true);

        OutputStreamWriter writer = null;
		try {
			writer = new OutputStreamWriter(conn.getOutputStream());
			System.out.print("should not print");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	

        try {
			writer.write(urls[1]);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
        try {
			writer.flush();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}

        String line = null;
        String toReturn = "";
        BufferedReader reader = null;
		try {
			reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
        
        try {
			while ((line = reader.readLine()) != null) {
			    toReturn += line;
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
        try {
			writer.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
        try {
			reader.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
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
