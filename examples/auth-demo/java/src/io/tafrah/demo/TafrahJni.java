package io.tafrah.demo;

public final class TafrahJni {
    static {
        String explicitPath = System.getProperty("tafrah.jni.path");
        if (explicitPath != null && !explicitPath.isEmpty()) {
            System.load(explicitPath);
        } else {
            System.loadLibrary("tafrah_jni");
        }
    }

    private TafrahJni() {}

    public static native String runDemoJson();
}
