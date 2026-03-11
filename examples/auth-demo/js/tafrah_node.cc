#include <node_api.h>

#include <stdexcept>
#include <string>

#include "demo_core.hpp"

namespace {

napi_value RunDemoJson(napi_env env, napi_callback_info) {
  try {
    const auto result = tafrah_demo::run_demo();
    const std::string json = tafrah_demo::result_to_json(result, "js");
    napi_value out;
    napi_status status = napi_create_string_utf8(env, json.c_str(), json.size(), &out);
    if (status != napi_ok) {
      napi_throw_error(env, nullptr, "failed to create JSON string");
      return nullptr;
    }
    return out;
  } catch (const std::exception& err) {
    napi_throw_error(env, nullptr, err.what());
    return nullptr;
  }
}

napi_value Init(napi_env env, napi_value exports) {
  napi_value fn;
  napi_status status =
      napi_create_function(env, "runDemoJson", NAPI_AUTO_LENGTH, RunDemoJson, nullptr, &fn);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "failed to create runDemoJson");
    return nullptr;
  }

  status = napi_set_named_property(env, exports, "runDemoJson", fn);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "failed to export runDemoJson");
    return nullptr;
  }

  return exports;
}

}  // namespace

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
