#ifndef SERIALIZATION_H_
#define SERIALIZATION_H_

#include <iostream> 
#include <map>
#include <vector>
#include <string>
#include <string.h>
#include <stdio.h>
#include "flatbuffers/model_generated.h"

// using namespace secagg;

void serialize(std::map<std::string, std::vector<double>> model,
                            uint8_t** serialized_buffer,
                            int* serialized_buffer_size) {
    // Serialize string:float[] map into SSSS:[VVVVVVVV]

    // std::vector<unsigned char> serialized;
    // 
    // for (const auto &[name, values]: model) {
    //     for (char const &c: name) {
    //         serialized.push_back(c);
    //     }
    //     serialized.push_back(':');
    //     serialized.push_back('[');
    //     for (const double &val: values) {
    //         std::string val_string = std::to_string(val);
    //         for (char const &c: val_string) {
    //             serialized.push_back(c);
    //         }
    //         serialized.push_back(',');
    //     }
    //     serialized.push_back(']');
    //     serialized.push_back('/');
    // }
    // 
    // std::string s(serialized.begin(), serialized.end());
    // return s;

    flatbuffers::FlatBufferBuilder builder;
    std::vector<flatbuffers::Offset<KVPair>> features;
    for (const auto &[name, values]: model) {
        auto key = builder.createString(name);
        auto value = builder.CreateVector(values, values.size());
        auto kvpair = secagg::CreateKVPair(builder, key, value);
        features.push_back(kvpair);
    }
    auto model_features = builder.CreateVector(features);
    auto model = secagg::CreateModel(builder, model_features);
    builder.finish(model);

    uint8_t* model_buffer = builder.GetBufferPointer();
    int model_buffer_size = builder.GetSize();

    *serialized_buffer = model_buffer;
    *serialized_buffer_size = model_buffer_size;
}

std::map<std::string, std::vector<double>> deserialize(uint8_t* serialized_buffer) {
    // // Splits each entry on '/'
    // std::vector<std::string> entries; 
    // std::string delimitEntries = "/";
    // size_t pos = 0;
    // 
    // while ((pos = serialized_str.find(delimitEntries)) != std::string::npos) {
    //     std:: string token = serialized_str.substr(0, pos);
    //     entries.push_back(token);
    //     serialized_str.erase(0, pos+delimitEntries.length());
    // }
    // 
    // // Recreate the original map entries
    // std::map<std::string, std::vector<double>> demodel;
    // for (const std::string &entry: entries) {
    //     std::string delimiter = ":";
    //     std::string key = entry.substr(0, entry.find(delimiter));
    //     std::string values = entry.substr(entry.find(delimiter), entry.length());
    //     // values.length()-3 to remove trailing characters at the end (:[ and ])
    //     values = values.substr(2, values.length()-3);
    //     std::vector<double> newValues;
    //     pos = 0;
    //     std::string delimitValues = ",";
    //     while ((pos = values.find(",")) != std::string::npos) {
    //         std::string value = values.substr(0, pos);
    //         double valueDouble = ::atof(value.c_str());
    //         newValues.push_back(valueDouble);
    //         values.erase(0, pos+delimitValues.length());
    //     }
    //     demodel.insert({key, newValues});
    // }
    // 
    // return demodel;
    // END DESERIALIZATION
    std::map<std::string, std::vector<double>> demodel;

    auto model = secagg::GetModel(serialized_buffer);
    auto kvpairs = model->kv();
    auto num_kvs = kvpairs->size();
    for (int i = 0; i < num_kvs; i++) {
        std::vector<double> feature_values;
        auto pair = kvpairs->Get(i);
        // Key is a string
        auto key = pair->key()->str();
        auto value = pair->value();
        for (int j = 0; j < value->size(); j++) {
            auto feature_value = value->Get(j);
            feature_values.push_back(feature_value);
        }
        demodel.insert({key, feature_values});
    }
    return demodel;

}

#endif 
