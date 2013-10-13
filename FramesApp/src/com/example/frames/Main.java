package com.example.frames;



import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Array;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
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
import org.apache.http.util.EntityUtils;

import android.graphics.Bitmap;
import android.hardware.Camera;
import android.hardware.Camera.Parameters;
import android.hardware.Camera.PictureCallback;
import android.hardware.Camera.Size;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.provider.MediaStore;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.util.Log;
import android.view.Menu;
import android.view.View;
import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.Toast;


public class Main extends Activity {
	private WebView webview;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        
        WebView webview = (WebView) findViewById(R.id.webview);
        WebSettings webSettings = webview.getSettings();
        webview.addJavascriptInterface(new WebAppInterface(this), "Android");
        webSettings.setJavaScriptEnabled(true);
        
        webview.setWebViewClient(new WebViewClient());
        webview.loadUrl("file:///android_asset/index.html");
        System.out.println("asdfasdf");
        
    }
    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        //getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }
    private static final int CAPTURE_IMAGE_ACTIVITY_REQUEST_CODE = 100;
    public Uri fileUri;
    public void onOpen(){
    	
    	Intent intent = new Intent(MediaStore.ACTION_IMAGE_CAPTURE);

        fileUri = getOutputMediaFileUri(MEDIA_TYPE_IMAGE);
        // create a file to save the image
        intent.putExtra(MediaStore.EXTRA_OUTPUT, fileUri); // set the image file name
        //intent.putExtra(MediaStore.EXTRA_OUTPUT, MyFileContentProvider.CONTENT_URI);
        
        // start the image capture Intent
        startActivityForResult(intent, CAPTURE_IMAGE_ACTIVITY_REQUEST_CODE);
//    	Intent cameraIntent=new Intent(android.provider.MediaStore.ACTION_IMAGE_CAPTURE); 
//    	startActivityForResult(cameraIntent, 1); 
        
        
    }
    public void showToast(String toast) {
        Toast.makeText(this, toast, Toast.LENGTH_SHORT).show();
    }
    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == CAPTURE_IMAGE_ACTIVITY_REQUEST_CODE) {
            if (resultCode == RESULT_OK) {
//                File image = null;
//                try {
//					image = new File(new URI(getRealPathFromURI(fileUri)));
//				} catch (URISyntaxException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				}
               
            	Location myLocation = getLastBestLocation();
            	System.out.println("before post");
                
                
                double[] coords = new double[2];
                coords[0] = myLocation.getLongitude();
                coords[1] = myLocation.getLatitude();
                System.out.println("Yay coordinates: " + coords[0] + ", " + coords[1]);
                Poster(coords);
                
				}
            } else if (resultCode == RESULT_CANCELED) {
                // User cancelled the image capture
            } else {
                // Image capture failed, advise user
            }
        }

    public static String nameOfFile(){
    	return mediaFile.getPath();
    }
    public String getRealPathFromURI(Uri contentUri) {
    	
        String[] proj = { MediaStore.Video.Media.DATA };
        Cursor cursor = managedQuery(contentUri, proj, null, null, null);
        int column_index = cursor.getColumnIndexOrThrow(MediaStore.Images.Media.DATA);
        cursor.moveToFirst();
        return cursor.getString(column_index);
    }
    public File fileToReturn = null;
    private static Uri getOutputMediaFileUri(int type){
    	File fileToReturn =  getOutputMediaFile(type);
		System.out.println("WEEOHWEEWEEEOHHH");

        return  fileToReturn!=null?Uri.fromFile(fileToReturn):  
        null;
  }

    public static final int MEDIA_TYPE_IMAGE = 1;
    public static final int MEDIA_TYPE_VIDEO = 2;
    public static File mediaFile = null;
  /** Create a File for saving an image or video */
  private static File getOutputMediaFile(int type){
      // To be safe, you should check that the SDCard is mounted
      // using Environment.getExternalStorageState() before doing this.
	  
      File mediaStorageDir = new File(Environment.getExternalStoragePublicDirectory(
                Environment.DIRECTORY_PICTURES), "MyCameraApp");
      // This location works best if you want the created images to be shared
      // between applications and persist after your app has been uninstalled.

      // Create the storage directory if it does not exist
      if (! mediaStorageDir.exists()){
          if (! mediaStorageDir.mkdirs()){
              Log.d("MyCameraApp", "failed to create directory");
              return null;
          }
      }

      // Create a media file name
      String timeStamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
      //File mediaFile;
      if (type == MEDIA_TYPE_IMAGE){
          mediaFile = new File(mediaStorageDir.getPath() + File.separator +
          "IMG_"+ timeStamp + ".jpg");
      } else if(type == MEDIA_TYPE_VIDEO) {
          mediaFile = new File(mediaStorageDir.getPath() + File.separator +
          "VID_"+ timeStamp + ".mp4");
      } else {
          return null;
      }

	
      return mediaFile;
  }

  public static String encodeFromFile( File file )
		    throws java.io.IOException {
		        
		        String encodedData = null;
		        Base64.InputStream bis = null;
		        try
		        {
		            // Set up some useful variables
		            byte[] buffer = new byte[ Math.max((int)(file.length() * 1.4+1),40) ]; // Need max() for math on small files (v2.2.1); Need +1 for a few corner cases (v2.3.5)
		            int length   = 0;
		            int numBytes = 0;
		            
		            // Open a stream
		            bis = new Base64.InputStream( 
		                      new java.io.BufferedInputStream( 
		                      new java.io.FileInputStream( file ) ), Base64.ENCODE );
		            
		            // Read until done
		            while( ( numBytes = bis.read( buffer, length, 4096 ) ) >= 0 ) {
		                length += numBytes;
		            }   // end while
		            
		            // Save in a variable to return
		            encodedData = new String( buffer, 0, length, Base64.PREFERRED_ENCODING );
		                
		        }   // end try
		        catch( java.io.IOException e ) {
		            throw e; // Catch and release to execute finally{}
		        }   // end catch: java.io.IOException
		        finally {
		            try{ bis.close(); } catch( Exception e) {}
		        }   // end finally
		        
		        return encodedData;
		        }
	public static void Poster(double[] coords){
		System.setProperty("http.agent", "Frames");
        String urlParameters = "";
		try {
			urlParameters = "picture=" + encodeImage(mediaFile).replace("+", "%2B").replace("\n", "") + "location=" + Arrays.toString(coords).replace("[", "").replace("]","");
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			return ;
		}
		new Post().execute("http://frames-app.appspot.com/image", urlParameters);
	}

//		HttpClient httpclient = new DefaultHttpClient();
//		HttpPost httppost = new HttpPost("http://frames-app.appspot.com/image/");
//
//		// Request parameters and other properties.
//		List<NameValuePair> params = new ArrayList<NameValuePair>(2);
//		params.add(new BasicNameValuePair("picture", encodeFromFile(getOutputMediaFile(1))));
//		params.add(new BasicNameValuePair("location", "40,-72!"));
//		httppost.setEntity(new UrlEncodedFormEntity(params, "UTF-8"));
//
//		//Execute and get the response.
//		HttpResponse response = httpclient.execute(httppost);
//		HttpEntity entity = response.getEntity();
//
//		if (entity != null) {
//		    InputStream instream = entity.getContent();
//		    try {
//		        // do something useful
//		    } finally {
//		        instream.close();
//		    }
//		}
	


  public static String encodeImage(File file) throws IOException {
     
      return encodeFromFile(file);
  }

	public Location currentBestLocation = null;
	public Location getLastBestLocation() {
		LocationManager mLocationManager = (LocationManager) this.getSystemService(Context.LOCATION_SERVICE);
	    Location locationGPS = mLocationManager.getLastKnownLocation(LocationManager.GPS_PROVIDER);
	    Location locationNet = mLocationManager.getLastKnownLocation(LocationManager.NETWORK_PROVIDER);

	    long GPSLocationTime = 0;
	    if (null != locationGPS) { GPSLocationTime = locationGPS.getTime(); }

	    long NetLocationTime = 0;
	    
	    if (null != locationNet) {
	        NetLocationTime = locationNet.getTime();
	    }

	    if ( 0 < GPSLocationTime - NetLocationTime ) {
	        return locationGPS;
	    }
	    else{
	        return locationNet;
	    }

	}


    
    
}
