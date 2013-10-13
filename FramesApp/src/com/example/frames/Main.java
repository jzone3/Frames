package com.example.frames;



import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

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
        webview.loadUrl("file:///android_asset/Index.html");
        
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

        fileUri = getOutputMediaFileUri(MEDIA_TYPE_IMAGE); // create a file to save the image
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
                Post(mediaFile);
            	Location myLocation = null;
            	try{
            		myLocation = getLastBestLocation();
            	}catch(Exception e){
            		showToast("Error: Location services are disabled.");
            	}
                
                
                double[] coords = new double[2];
                coords[0] = myLocation.getLongitude();
                coords[1] = myLocation.getLatitude();
                System.out.println("Yay coordinates: " + coords[0] + ", " + coords[1]);
            } else if (resultCode == RESULT_CANCELED) {
                // User cancelled the image capture
            } else {
                // Image capture failed, advise user
            }
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
    private static Uri getOutputMediaFileUri(int type){
    	File fileToReturn =  getOutputMediaFile(type);
        return  fileToReturn!=null?Uri.fromFile(fileToReturn):  
        null;
  }

    public static final int MEDIA_TYPE_IMAGE = 1;
    public static final int MEDIA_TYPE_VIDEO = 2;
    public static File mediaFile;
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

	
	private String Post(File file) {
		System.setProperty("http.agent", "PicShare");
      String urlParameters = "";
		try {
			urlParameters = "image=" + encodeImage(file).replace("+", "%2B");
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			return "hello-3";
		}
		
      
      URL url = null;
      try {
      	url = new URL("https://frames-app.appspot.com/");
      } catch (Exception e) {
      	// TODO Auto-generated catch block
      	e.printStackTrace();
      	return "hello-2";
      }
      
      URLConnection conn = null;
		try {
			conn = url.openConnection();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return "hello-1";
		}
		
      conn.setDoOutput(true);

      OutputStreamWriter writer = null;
		try {
			writer = new OutputStreamWriter(conn.getOutputStream());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return "hello0";
		}

      try {
			writer.write(urlParameters);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return "hello1";
		}
      try {
			writer.flush();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return "hello2";
		}

      String line = null;
      String toReturn = "";
      BufferedReader reader = null;
		try {
			reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return "Server error. Try again.";
		}
      
      try {
			while ((line = reader.readLine()) != null) {
			    toReturn += line;
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return "hello4";
		}
      try {
			writer.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return "hello5";
		}
      try {
			reader.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return "hello6";
		}
      
      return toReturn;
	}
	public static String encodeFromFile( File file )
          throws java.io.IOException {
             
              String encodedData = null;
              Base64.InputStream bis = null;
              try
              {
                  // Set up some useful variables
                  byte[] buffer = new byte[ Math.max((int)(file.length() * 1.4+1),40) ];
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
                  encodedData = new String( buffer, 0, length, "US-ASCII" );
                     
              }   // end try
              catch( java.io.IOException e ) {
                  throw e; // Catch and release to execute finally{}
              }   // end catch: java.io.IOException
              finally {
                  try{ bis.close(); } catch( Exception e) {}
              }   // end finally
             
              return encodedData;
              }
  public static String encodeImage(File file) throws IOException {
     
      return encodeFromFile(file);
  }

	private Location currentBestLocation = null;
	private Location getLastBestLocation() {
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
