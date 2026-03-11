#include <jni.h>

#include <stdexcept>
#include <string>

#include "demo_core.hpp"

extern "C" JNIEXPORT jstring JNICALL
Java_io_tafrah_demo_TafrahJni_runDemoJson(JNIEnv* env, jclass) {
  try {
    const auto result = tafrah_demo::run_demo();
    const std::string json = tafrah_demo::result_to_json(result, "java");
    return env->NewStringUTF(json.c_str());
  } catch (const std::exception& err) {
    jclass ex = env->FindClass("java/lang/RuntimeException");
    if (ex != nullptr) {
      env->ThrowNew(ex, err.what());
    }
    return nullptr;
  }
}
