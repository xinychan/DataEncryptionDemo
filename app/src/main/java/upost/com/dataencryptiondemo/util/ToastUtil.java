package upost.com.dataencryptiondemo.util;

import android.content.Context;
import android.widget.Toast;

/**
 * Toast的工具类
 */

public class ToastUtil {

    private static Toast toast;

    public static void showToast(Context context, String content){
        if (toast==null) {
            toast = Toast.makeText(context, content, Toast.LENGTH_SHORT);
        }else {
            toast.setText(content);
        }
        toast.show();
    }

}
