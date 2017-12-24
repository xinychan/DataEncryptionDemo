package upost.com.dataencryptiondemo.util;

import android.util.Log;

/**
 * Created by xinychan on 2017/12/25.
 */

public class LogUtil {

    private static String TAG = "mytag";

    public static void showLog(String str) {
        Log.d(TAG, str);
    }
}
