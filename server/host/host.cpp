//#include <openenclave/host.h>
#include <stdio.h>

//#include "enclave.h"

#include "encryption/encrypt.h"
#include "encryption/serialization.h"
#include "utils.h"

// Include the untrusted modelaggregator header that is generated
// during the build. This file is generated by calling the
// sdk tool oeedger8r against the modelaggregator.edl file.
//#include "modelaggregator_u.h"

using namespace std;

//char* path = "/home/ubuntu/test/secure-aggregation/server/build/enclave/enclave.signed";
//uint32_t flags = OE_ENCLAVE_FLAG_DEBUG | OE_ENCLAVE_FLAG_SIMULATE;

// Helper function used to copy double pointers from untrusted memory to enclave memory
void copy_arr_to_enclave(uint8_t* dst[], size_t num, uint8_t* src[], size_t lengths[]) {
  for (int i = 0; i < num; i++) {
    size_t nlen = lengths[i];
    dst[i] = new uint8_t[nlen];
    memcpy((void*) dst[i], (const void*) src[i], nlen);
  }
}

// This is the function that the host calls. It performs
// the aggregation and encrypts the new model to pass back.
void fake_enclave_modelaggregator(uint8_t*** encrypted_accumulator,
    size_t* accumulator_lengths,
    size_t accumulator_length, 
    uint8_t** encrypted_old_params, 
    size_t old_params_length, 
    uint8_t*** encrypted_new_params_ptr,
    size_t* new_params_length)
{
  fprintf(stderr, "HERE in ENCLAVE\n");
  // Ciphertext, IV, and tag are required for decryption.
  size_t encryption_metadata_length = 3;

  // We need to copy double pointers in the function arguments over to
  // enclave memory. Otherwise, the host can manipulate their contents.
  uint8_t* encrypted_old_params_cpy[encryption_metadata_length];
  size_t lengths[] = {old_params_length * sizeof(uint8_t), CIPHER_IV_SIZE, CIPHER_TAG_SIZE};
  copy_arr_to_enclave(encrypted_old_params_cpy,
      encryption_metadata_length, 
      encrypted_old_params,
      lengths);
  fprintf(stderr, "Copied arrs\n");
  uint8_t* serialized_old_params = new uint8_t[old_params_length * sizeof(uint8_t)];
  decrypt_bytes(encrypted_old_params_cpy[0],
      encrypted_old_params_cpy[1],
      encrypted_old_params_cpy[2],
      old_params_length,
      &serialized_old_params);

  fprintf(stderr, "Decrypted\n");
  map<string, vector<double>> old_params = deserialize(serialized_old_params);
  fprintf(stderr, "Deserialized\n");

  vector<map<string, vector<double>>> accumulator;
  set<string> vars_to_aggregate;

  // This for loop decrypts the accumulator and adds all
  // variables received by the clients into a set.
  for (int i = 0; i < accumulator_length; i++) {
    // Copy double pointers to enclave memory again.
    uint8_t** encrypted_accumulator_i_cpy = new uint8_t*[encryption_metadata_length * sizeof(uint8_t*)];
    size_t lengths[] = {accumulator_lengths[i] * sizeof(uint8_t), CIPHER_IV_SIZE, CIPHER_TAG_SIZE};
    copy_arr_to_enclave(encrypted_accumulator_i_cpy,
        encryption_metadata_length,
        encrypted_accumulator[i],
        lengths);

    uint8_t* serialized_accumulator = new uint8_t[accumulator_lengths[i] * sizeof(uint8_t)];
    decrypt_bytes(encrypted_accumulator_i_cpy[0],
        encrypted_accumulator_i_cpy[1],
        encrypted_accumulator_i_cpy[2],
        accumulator_lengths[i],
        &serialized_accumulator);

    map<string, vector<double>> acc_params = deserialize(serialized_accumulator);

    delete_double_ptr(encrypted_accumulator_i_cpy, encryption_metadata_length);
    delete serialized_accumulator;

    for (const auto& pair : acc_params) {
      if (pair.first != "_contribution" && !(pair.first.rfind("shape", 0) == 0)) {
        vars_to_aggregate.insert(pair.first);
      }
    }

    accumulator.push_back(acc_params);
  }
  fprintf(stderr, "Accumulated\n");

  // We iterate through all weights names received by the clients.
  int i = 0;
  int total = vars_to_aggregate.size();
  for (string v_name : vars_to_aggregate) {
    double iters_sum = 0;
    vector<vector<double>> vars;

    fprintf(stderr, "(%d of %d) %s\n", i++, total, v_name);
    // For each accumulator, we find the vector of the current weight and
    // multiple all of it's elements by local iterations. We keep a running
    // sum of total iterations and a vector of all weights observed.
    for (map<string, vector<double>> acc_params : accumulator) {
      if (acc_params.find(v_name) == acc_params.end()) { // This accumulator doesn't have the given variable
        continue;
      }
      //print_map_keys(acc_params);

      //fprintf(stderr, "0\n");
      // Each params map will have an additional key "_contribution" to hold the number of local iterations.
      //if (acc_params.count("_contribution") > 0)
        //fprintf(stderr, "Key found\n");
      //else
        //fprintf(stderr, "Key NOT found\n");

      double n_iter = 1; //acc_params["_contribution"][0];
      iters_sum += n_iter;
      //fprintf(stderr, "1\n");

      // Multiple the weights by local iterations.
      vector<double>& weights = acc_params[v_name];
      //fprintf(stderr, "2\n");
      for_each(weights.begin(), weights.end(), [&n_iter](double& d) { d *= n_iter; });
      //fprintf(stderr, "3\n");
      vars.push_back(weights);
      //fprintf(stderr, "4\n");
    }

    if (iters_sum == 0) {
      continue; // Didn't receive this variable from any clients
    }

    // Take the element-wise sum of all the weights and add it to the
    // old model parameters. Then, divide by the total iterations over
    // all clients that had this weight.
    for (int i = 0; i < old_params[v_name].size(); i++) {
      for (vector<double> weights : vars) {
        old_params[v_name][i] += weights[i];
      }
      old_params[v_name][i] /= iters_sum;
    }
    //fprintf(stderr, "5\n");
  }
  fprintf(stderr, "Aggregated\n");

  int serialized_buffer_size = 0;
  uint8_t* serialized_new_params = serialize(old_params, &serialized_buffer_size);

  uint8_t** encrypted_new_params = new uint8_t*[encryption_metadata_length * sizeof(uint8_t*)];
  encrypted_new_params[0] = new uint8_t[serialized_buffer_size * sizeof(uint8_t)];
  encrypted_new_params[1] = new uint8_t[CIPHER_IV_SIZE * sizeof(uint8_t)];
  encrypted_new_params[2] = new uint8_t[CIPHER_TAG_SIZE * sizeof(uint8_t)];
  encrypt_bytes(serialized_new_params, serialized_buffer_size, encrypted_new_params);

  // Need to copy the encrypted model, IV, and tag over to untrusted memory.
  *encrypted_new_params_ptr = (uint8_t**) malloc(encryption_metadata_length * sizeof(uint8_t*));
  *new_params_length = serialized_buffer_size;
  size_t item_lengths[3] = {*new_params_length, CIPHER_IV_SIZE, CIPHER_TAG_SIZE};
  for (int i = 0; i < encryption_metadata_length; i++) {
    (*encrypted_new_params_ptr)[i] = (uint8_t*) malloc(item_lengths[i] * sizeof(uint8_t));
    memcpy((void *) (*encrypted_new_params_ptr)[i], (const void*) encrypted_new_params[i], item_lengths[i] * sizeof(uint8_t));
  }
  fprintf(stderr, "Done\n");

  delete_double_ptr(encrypted_new_params, encryption_metadata_length);
}

// This is the function that the Python code will call into.
// Returns 0 on success.
int host_modelaggregator(uint8_t*** encrypted_accumulator, 
        size_t* accumulator_lengths,
        size_t accumulator_length, 
        uint8_t** encrypted_old_params,
        size_t old_params_length,
        uint8_t*** encrypted_new_params_ptr,
        size_t* new_params_length)
{
    //oe_result_t error;
    // Create the enclave
    //Enclave enclave(path, flags);
    //error = enclave.getEnclaveRet();
    //if (error != OE_OK)
    //{
    //    fprintf(
    //        stderr,
    //        "oe_create_modelaggregator_enclave(): result=%u (%s)\n",
    //        error,
    //        oe_result_str(error));
    //    return NULL;
    //}
    std::cout << "Callling fake enclave" << std::endl;
    fake_enclave_modelaggregator( encrypted_accumulator, 
            accumulator_lengths, 
            accumulator_length, 
            encrypted_old_params, 
            old_params_length, 
            encrypted_new_params_ptr,
            new_params_length);

    //error = enclave_modelaggregator(enclave.getEnclave(), 
    //        encrypted_accumulator, 
    //        accumulator_lengths, 
    //        accumulator_length, 
    //        encrypted_old_params, 
    //        old_params_length, 
    //        encrypted_new_params_ptr,
    //        new_params_length);
    //if (error != OE_OK)
    //{
    //    fprintf(
    //        stderr,
    //        "calling into enclave_modelaggregator failed: result=%u (%s)\n",
    //        error,
    //        oe_result_str(error));
    //    return 1;
    //}

    return 0;
}

