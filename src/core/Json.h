// nlohmann::json plus type-checked getters. The API sends explicit nulls and
// sometimes numbers where strings are expected, so every read goes through
// these helpers instead of json::value(), which throws on type mismatches.
#pragma once
#include "nlohmann/json.hpp"
#include <cstdint>
#include <string>

namespace pvpn {

typedef nlohmann::json Json;

inline const Json* JsonMember(const Json& object, const char* key)
{
    if (!object.is_object())
        return nullptr;
    auto it = object.find(key);
    if (it == object.end() || it->is_null())
        return nullptr;
    return &*it;
}

inline std::string JsonString(const Json& object, const char* key, const std::string& fallback = "")
{
    const Json* value = JsonMember(object, key);
    if (value == nullptr)
        return fallback;
    if (value->is_string())
        return value->get<std::string>();
    if (value->is_number_integer())
        return std::to_string(value->get<int64_t>());
    return fallback;
}

inline int64_t JsonInt(const Json& object, const char* key, int64_t fallback = 0)
{
    const Json* value = JsonMember(object, key);
    if (value == nullptr)
        return fallback;
    if (value->is_number())
        return value->get<int64_t>();
    if (value->is_boolean())
        return value->get<bool>() ? 1 : 0;
    if (value->is_string()) {
        try {
            return std::stoll(value->get<std::string>());
        } catch (...) {
        }
    }
    return fallback;
}

inline double JsonDouble(const Json& object, const char* key, double fallback = 0)
{
    const Json* value = JsonMember(object, key);
    if (value == nullptr || !value->is_number())
        return fallback;
    return value->get<double>();
}

inline bool JsonBool(const Json& object, const char* key, bool fallback = false)
{
    const Json* value = JsonMember(object, key);
    if (value == nullptr)
        return fallback;
    if (value->is_boolean())
        return value->get<bool>();
    if (value->is_number())
        return value->get<double>() != 0;
    return fallback;
}

inline const Json& JsonArray(const Json& object, const char* key)
{
    static const Json kEmpty = Json::array();
    const Json* value = JsonMember(object, key);
    return value != nullptr && value->is_array() ? *value : kEmpty;
}

inline const Json& JsonObject(const Json& object, const char* key)
{
    static const Json kEmpty = Json::object();
    const Json* value = JsonMember(object, key);
    return value != nullptr && value->is_object() ? *value : kEmpty;
}

// Parses without exceptions; returns a discarded value (is_discarded()) on error.
inline Json ParseJson(const std::string& text)
{
    return Json::parse(text, nullptr, false);
}

}  // namespace pvpn
