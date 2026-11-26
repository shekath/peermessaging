# libsignal uses JNI — keep its classes intact.
-keep class org.signal.libsignal.** { *; }
-keep class net.zetetic.database.** { *; }
-keepclassmembers class * implements java.io.Serializable { *; }

# Strip all logging from release builds so nothing sensitive reaches logcat.
-assumenosideeffects class android.util.Log {
    public static *** v(...);
    public static *** d(...);
    public static *** i(...);
    public static *** w(...);
    public static *** e(...);
}
-repackageclasses ''
-allowaccessmodification
