package org.sandroproxy.plugin.gui;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

import org.sandrop.webscarab.model.Preferences;
import org.sandrop.webscarab.model.StoreException;
import org.sandrop.webscarab.plugin.Framework;
import org.sandrop.webscarab.plugin.proxy.IClientResolver;
import org.sandrop.webscarab.plugin.proxy.Proxy;
import org.sandrop.webscarab.plugin.proxy.ProxyPlugin;
import org.sandroproxy.logger.Logger;
import org.sandroproxy.plugin.R;
import org.sandroproxy.proxy.plugin.CustomPlugin;
import org.sandroproxy.utils.NetworkHostNameResolver;
import org.sandroproxy.utils.PreferenceUtils;
import org.sandroproxy.utils.network.ClientResolver;
import org.sandroproxy.web.SandroProxyWebService;
import org.sandroproxy.webscarab.store.sql.SqlLiteStore;

import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.preference.PreferenceManager;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.MenuItem.OnMenuItemClickListener;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.View.OnLongClickListener;
import android.widget.TextView;
import android.widget.Toast;
import android.widget.ToggleButton;

public class MainActivity extends Activity {
    
    private static Framework framework = null;
    private static String TAG = MainActivity.class.getName();
    private static boolean LOGD = false;
    
    
    public static boolean proxyStarted = false;
    
    private static Handler mHandlerLog = null;
    private static TextView mLogView;
    
    private static Logger mLogger;
    private static int MAX_LOG_SIZE = 20000;
    private static int MAX_MSG_SIZE = 3000;
    private static String mLogWindowMessage = "";
    
    private static boolean mInitChecked = false;
    
    NetworkHostNameResolver networkHostNameResolver = null;
    IClientResolver clientResolver = null;
    
    private static String ACTION_INSTALL = "android.credentials.INSTALL";
    private static String EXTRA_CERTIFICATE = "CERT";
    
    private static java.util.logging.Logger logger = java.util.logging.Logger.getLogger(MainActivity.class.getName());

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        logger.setLevel(Level.FINEST);
        mLogView = (TextView) findViewById(R.id.logView); 
        ToggleButton toggleButton = (ToggleButton) findViewById(R.id.toggleButtonOnOff);
        toggleButton.setOnClickListener(new OnClickListener() {
            
            @Override
            public void onClick(View v) {
                boolean value = ((ToggleButton)v).isChecked();
                if (value && !proxyStarted){
                    // start
                    Thread thread = new Thread()
                    {
                        @Override
                        public void run() {
                            Preferences.init(getApplicationContext());
                            if (isDeviceRooted()){
                                ipTablesForTransparentProxy(true);
                            }
                            framework = new Framework(getApplicationContext());
                            setStore(getApplicationContext());
                            networkHostNameResolver = new NetworkHostNameResolver(getApplicationContext());
                            clientResolver = new ClientResolver(getApplicationContext());
                            Proxy proxy = new Proxy(framework, networkHostNameResolver, clientResolver);
                            framework.addPlugin(proxy);
                            if (true){
                                ProxyPlugin plugin = new CustomPlugin();
                                proxy.addPlugin(plugin);
                            }
                            proxy.run();
                            proxyStarted = true;
                            logger.fine("Android os proxy should point to localhost 9008");
                        }
                    };
                    thread.setName("Starting proxy");
                    thread.start();
                }else if (proxyStarted){
                    //stop
                    Thread thread = new Thread()
                    {
                        @Override
                        public void run() {
                            if (isDeviceRooted()){
                                ipTablesForTransparentProxy(false);
                            }
                            if (framework != null){
                                framework.stop();
                            }
                            if (networkHostNameResolver != null){
                                networkHostNameResolver.cleanUp();
                            }
                            networkHostNameResolver = null;
                            framework = null;
                            proxyStarted = false;
                        }
                    };
                    thread.setName("Stoping proxy");
                    thread.start();
                }
            }
        });
        
        if (mHandlerLog == null){
            mHandlerLog =new Handler() {
                @Override
                public void handleMessage(Message msg) {
                    String previousText = mLogWindowMessage;
                    String message = (String)msg.obj;
                    if (message.length() > MAX_MSG_SIZE){
                        message = message.substring(0,MAX_MSG_SIZE);
                    }
                    String newText = message + previousText;
                    int newSize = newText.length();
                    if (newSize > MAX_LOG_SIZE){
                        int size = MAX_LOG_SIZE - (MAX_LOG_SIZE / 4);
                        newText = newText.substring(0, size);
                    }
                    mLogWindowMessage = newText;
                    mLogView.setText(mLogWindowMessage);
                }
            };
        }
        if (mLogger == null){
            mLogger = new Logger(mHandlerLog);
        }
        
        // long click clears the message window
        mLogView.setOnLongClickListener(new OnLongClickListener() {
            @Override
            public boolean onLongClick(View v) {
                ((TextView)v).setText("");
                mLogWindowMessage = "";
                return false;
            }
        });
        
        // set some values if needed
        if (!mInitChecked){
            initValues();
            mInitChecked = true;
        }
        
        mLogView.setText(mLogWindowMessage);
    }
    
    @Override 
    public boolean onCreateOptionsMenu(Menu menu) {
        
        MenuItem itemOnOfProxy = menu.add("On/Off");
        if (SandroProxyWebService.webServerStarted){
            itemOnOfProxy.setIcon(R.drawable.ic_menu_close_clear_cancel);
        }else{
            itemOnOfProxy.setIcon(R.drawable.ic_menu_play_clip);
        }
        
        itemOnOfProxy.setShowAsAction(MenuItem.SHOW_AS_ACTION_ALWAYS | MenuItem.SHOW_AS_ACTION_COLLAPSE_ACTION_VIEW);
        itemOnOfProxy.setOnMenuItemClickListener(new OnMenuItemClickListener() {
            
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                    AsyncTask<Boolean, Void, Boolean> startStop = new AsyncTask<Boolean, Void, Boolean>(){
                        @Override
                        protected Boolean doInBackground(Boolean... params) {
                            if (SandroProxyWebService.webServerStarted){
                                try {
                                    Intent service = new Intent(getApplicationContext(), SandroProxyWebService.class);
                                    stopService(service);
                                } catch (Exception e) {
                                    e.printStackTrace();
                                }
                                
                            }else{
                                try {
                                    Intent service = new Intent(getApplicationContext(), SandroProxyWebService.class);
                                    startService(service);
                                } catch (Exception e) {
                                    e.printStackTrace();
                                }
                            }
                            
                            return true;
                        }
                    };
                    startStop.execute(SandroProxyWebService.webServerStarted);
                    if (SandroProxyWebService.webServerStarted){
                        item.setIcon(R.drawable.ic_menu_play_clip);
                    }else{
                        item.setIcon(R.drawable.ic_menu_close_clear_cancel);
                    }
                return true;
            }
        });
        
        // export ca to android store
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.ICE_CREAM_SANDWICH){
            MenuItem itemIpTablesClear = menu.add("Export CA to store");
            itemIpTablesClear.setIcon(R.drawable.ic_menu_set_as);
            itemIpTablesClear.setShowAsAction(MenuItem.SHOW_AS_ACTION_ALWAYS);
            final Context context = this;
            itemIpTablesClear.setOnMenuItemClickListener(new OnMenuItemClickListener() {
                @Override
                public boolean onMenuItemClick(MenuItem item) {
                    AsyncTask<Void, Void, Void> exportCaToStoreTask = new AsyncTask<Void, Void, Void>(){
                        @Override
                        protected Void doInBackground(Void... params) {
                            exportCACertToUserStore(context);
                            return null;
                        }
                    };
                    exportCaToStoreTask.execute((Void[])null);
                    return true;
                }
            });
        }
        // clear iptables
        if (isDeviceRooted()){
            MenuItem itemIpTablesClear = menu.add("Clear iptables");
            itemIpTablesClear.setIcon(R.drawable.ic_menu_compass);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.HONEYCOMB){
                itemIpTablesClear.setShowAsAction(MenuItem.SHOW_AS_ACTION_ALWAYS);
            }
            itemIpTablesClear.setOnMenuItemClickListener(new OnMenuItemClickListener() {
                @Override
                public boolean onMenuItemClick(MenuItem item) {
                    AsyncTask<Void, Void, Void> exportCaToStoreTask = new AsyncTask<Void, Void, Void>(){
                        @Override
                        protected Void doInBackground(Void... params) {
                            ipTablesForTransparentProxy(false);
                            return null;
                        }
                    };
                    exportCaToStoreTask.execute((Void[])null);
                    return true;
                }
            });
        }
        
        // clear captured data
        MenuItem itemDelete = menu.add("Delete captured data");
        itemDelete.setIcon(R.drawable.ic_menu_clear_playlist);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.HONEYCOMB){
            itemDelete.setShowAsAction(MenuItem.SHOW_AS_ACTION_ALWAYS);
        }
        itemDelete.setOnMenuItemClickListener(new OnMenuItemClickListener() {
            
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                AsyncTask<Void, Void, Boolean> deleteData = new AsyncTask<Void, Void, Boolean>(){
                    @Override
                    protected Boolean doInBackground(Void... params) {
                        File file = PreferenceUtils.getDataStorageDir(getApplicationContext());
                        String rootDirName = null;
                        if (file != null){
                            rootDirName = file.getAbsolutePath() + "/content";
                        }
                        File rootDir = new File(rootDirName);
                        File[] contentFiles = null;
                        if (file.exists()) {
                            // we create file list before we delete database
                            contentFiles = rootDir.listFiles();
                        }
                        SqlLiteStore database = SqlLiteStore.getInstance(getApplicationContext(), rootDirName);
                        database.clearHttpDatabase();
                        
                        DeleteFilesThread deleteFilesThread = new DeleteFilesThread(contentFiles);
                        deleteFilesThread.start();
                        
                        return true;
                    }
                    @Override protected void onPostExecute(Boolean result) {
                    }
                };
                deleteData.execute((Void[])null);
                return true;
            }
            
        });
        
        return true;
    }
    
    private class DeleteFilesThread extends Thread{
        private File[] filesToDelete;
        public DeleteFilesThread(File[] files){
            filesToDelete = files;
        }
        
        public void run() {
            if (filesToDelete != null){
                for (File contentFile : filesToDelete) {
                    try{
                        contentFile.delete();
                        logger.finest("File deleted: " + contentFile.getAbsolutePath());
                    }catch (Exception ex){
                        Log.e(TAG, ex.getMessage());
                    }
                }
            }
        }
    }
    
    public static void setStore(Context context){
        if (framework != null){
            try {
                File file =  PreferenceUtils.getDataStorageDir(context);
                if (file != null){
                    File rootDir = new File(file.getAbsolutePath() + "/content");
                    if (!rootDir.exists()){
                        rootDir.mkdir();
                    }
                    framework.setSession("Database", SqlLiteStore.getInstance(context, rootDir.getAbsolutePath()), "");
                }
            } catch (StoreException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
    }
    
    /*
     *  this will work only on sdk 14 or higher
     */
    public static void exportCACertToUserStore(Context context){
        
        Intent intent = new Intent(ACTION_INSTALL);
        intent.setClassName("com.android.certinstaller","com.android.certinstaller.CertInstallerMain");
        try {
            String keystoreCAExportFullPath = PreferenceUtils.getCAExportFilePath(context.getApplicationContext());
            File caExportFile = new File(keystoreCAExportFullPath);
            byte[] result = new byte[(int) caExportFile.length()];
            FileInputStream in = new FileInputStream(caExportFile);
            in.read(result);
            in.close();
            intent.putExtra(EXTRA_CERTIFICATE, result);
            context.startActivity(intent);
        }catch (Exception ex){
            ex.printStackTrace();
        }
    }
    
    
    /**
     * Checks if the device is rooted.
     * 
     * @return <code>true</code> if the device is rooted, <code>false</code>
     * otherwise.
     */
    public static boolean isDeviceRooted() {
      // get from build info
      boolean trueReturn = true;
      String buildTags = android.os.Build.TAGS;
      if (buildTags != null && buildTags.contains("test-keys")) {
          return trueReturn;
      }
      try {
       // check if /system/app/Superuser.apk is present
        {
            File file = new File("/system/app/Superuser.apk");
            if (file.exists()) {
              return trueReturn;
            }
        }
        // search for some typical locations
        {
            String[] suPlaces = { "/sbin/", "/system/bin/", "/system/xbin/", "/data/local/xbin/",
                    "/data/local/bin/", "/system/sd/xbin/", "/system/bin/failsafe/", "/data/local/" };
            for (String suPlace : suPlaces) {
                File file = new File(suPlace + "su");
                if (file.exists()) {
                    return trueReturn;
                }
            }
        }
      } catch (Throwable e1) {
        // ignore
      }
      return false;
    }
    
    
    private void ipTablesForTransparentProxy(boolean activate){
        int processId = getApplicationInfo().uid;
        String excludedUid = String.valueOf(processId);
        String action = "A";
        String chainName = "spplugin";
        String chainName1 = "sppluginOutput";
        List<String> rules = new ArrayList<String>();

        if (activate){
            action = "A";
            String createChainRule = "iptables --new " + chainName; rules.add(createChainRule);
            String createNatChainRule = "iptables -t nat --new " + chainName; rules.add(createNatChainRule);
            String createNatChainRule1 = "iptables -t nat --new " + chainName1; rules.add(createNatChainRule1);
        }else{
            action = "D";
            String dettachChainRule = "iptables -D INPUT -j " + chainName; rules.add(dettachChainRule);
            String dettachNatChainRule = "iptables -t nat -D PREROUTING -j " + chainName; rules.add(dettachNatChainRule);
            String dettachNatChainRule1 = "iptables -t nat -D OUTPUT -j " + chainName1; rules.add(dettachNatChainRule1);
        }
        
        // create 80 rules 
        String accept80Rule = "iptables -" + action + " " + chainName + " -p tcp --dport 80 -j ACCEPT "; rules.add(accept80Rule);
        String redirect80Rule = "iptables -" + action + " " + chainName + " -t nat -p tcp --dport 80 -j REDIRECT --to-port 8009 ";rules.add(redirect80Rule);
        String exclude80UidRule = "iptables -t nat -" + action + " " + chainName1 + " -m owner ! --uid-owner " + excludedUid + " -p tcp --dport 80 -j DNAT --to 127.0.0.1:8009 ";rules.add(exclude80UidRule);
        
        // create 443 rules 
        String accept443Rule = "iptables -" + action + " " + chainName + " -p tcp --dport 443 -j ACCEPT ";rules.add(accept443Rule);
        String redirect443Rule = "iptables -" + action + " " + chainName + " -t nat -p tcp --dport 443 -j REDIRECT --to-port 8010 ";rules.add(redirect443Rule);
        String exclude443UidRule = "iptables -t nat -" + action + " " + chainName1 + " -m owner ! --uid-owner " + excludedUid + " -p tcp --dport 443 -j DNAT --to 127.0.0.1:8010 ";rules.add(exclude443UidRule);
        
        if (activate){
            String attachChainRule = "iptables -A INPUT -j " + chainName; rules.add(attachChainRule);
            String attachNatChainRule = "iptables -t nat -A PREROUTING -j " + chainName; rules.add(attachNatChainRule);
            String attachNatChainRule1 = "iptables -t nat -A OUTPUT -j " + chainName1; rules.add(attachNatChainRule1);
        }else{
            
            String deleteChainRule = "iptables --delete-chain " + chainName; rules.add(deleteChainRule);
            String deleteNatChainRule = "iptables -t nat --delete-chain " + chainName; rules.add(deleteNatChainRule);
            String deleteNatChainRule1 = "iptables -t nat --delete-chain " + chainName1; rules.add(deleteNatChainRule1);
        }
        Process p;
        try {
            p = Runtime.getRuntime().exec(new String[]{"su", "-c", "sh"});
        
            DataOutputStream stdin = new DataOutputStream(p.getOutputStream());
            DataInputStream stdout = new DataInputStream(p.getInputStream());
            InputStream stderr = p.getErrorStream();
            
            for (String rule : rules) {
                logger.finest(rule);
                stdin.writeBytes(rule + "\n");
                stdin.writeBytes("echo $?\n");
                Thread.sleep(100);
                byte[] buffer = new byte[4096];
                int read = 0;
                String out = new String();
                String err = new String();
                while(true){
                    read = stdout.read(buffer);
                    out += new String(buffer, 0, read);
                    if(read<4096){
                        break;
                    }
                }
                while(stderr.available() > 0){
                    read = stderr.read(buffer);
                    err += new String(buffer, 0, read);
                    if(read < 4096){
                        break;
                    }
                }
                if (out != null && out.trim().length() > 0) logger.finest(out);
                if (err != null && err.trim().length() > 0) logger.finest(err);
            }
        } catch (Exception e) {
            e.printStackTrace();
            logger.finest("Error executing rules: " + e.getMessage());
        }
    }
    
    /*
     * TODO this should be handled with preference settings activity
     */
    private void initValues(){
        SharedPreferences pref = PreferenceManager.getDefaultSharedPreferences(this);
        
        // checking for directory to write data...
        String dirName = pref.getString(PreferenceUtils.dataStorageKey, null);
        if (dirName == null){
            File dataDir = getExternalCacheDir();
            if (PreferenceUtils.IsDirWritable(dataDir)){
                pref.edit().putString(PreferenceUtils.dataStorageKey, dataDir.getAbsolutePath()).commit();
            }else{
                Toast.makeText(this, R.string.data_storage_missing, Toast.LENGTH_LONG).show();
            }
        }else{
            File dataStorage = new File(dirName);
            if (!PreferenceUtils.IsDirWritable(dataStorage)){
                Toast.makeText(this, R.string.data_storage_missing, Toast.LENGTH_LONG).show();
            }
        }
        
        // if not set we set to 9008
        String port = pref.getString(PreferenceUtils.proxyPort, null);
        if (port == null){
            pref.edit().putString(PreferenceUtils.proxyPort, "9008").commit();
        }
        
        // by default we listen on all adapters
        boolean listenNonLocal = pref.getBoolean(PreferenceUtils.proxyListenNonLocal, false);
        if (!listenNonLocal){
            pref.edit().putBoolean(PreferenceUtils.proxyListenNonLocal, true).commit();
        }
        
        // we listen also for transparent flow 
        boolean transparentProxy = pref.getBoolean(PreferenceUtils.proxyTransparentKey, false);
        if (!transparentProxy){
            pref.edit().putBoolean(PreferenceUtils.proxyTransparentKey, true).commit();
        }
        
        // capture data to database
        boolean proxyCaptureData = pref.getBoolean(PreferenceUtils.proxyCaptureData, false);
        if (!proxyCaptureData){
            pref.edit().putBoolean(PreferenceUtils.proxyCaptureData, true).commit();
        }
    }
}
