# cython: language_level=3

from libcpp.string cimport string
from libcpp.vector cimport vector
from libcpp.map cimport map as mapcpp
from ctypes import c_ubyte
from libcpp.map cimport map as cmap
from libcpp.pair cimport pair as cpair
from libcpp.vector cimport vector
from cpython.mem cimport PyMem_Malloc, PyMem_Free

# TODO: Hold global interpreter lock upon PyMem_Malloc, PyMem_Free calls
# https://docs.python.org/3/c-api/memory.html
# Without holding the lock, these functions are not thread-safe

cdef extern from "../common/encryption/serialization.h":
    unsigned char* serialize(mapcpp[string, vector[float]] model, int* serialized_buffer_size)
    mapcpp[string, vector[float]] deserialize(unsigned char* serialized_buffer)

cdef extern from "../common/encryption/encrypt.h":
    void encrypt_bytes(unsigned char* model_data, size_t data_len, unsigned char*** ciphertext)
    void decrypt_bytes(unsigned char* model_data, unsigned char* iv, unsigned char* tag, size_t data_len, unsigned char** text)

cdef cmap[string, vector[float]] dict_to_cmap(dict the_dict):
    """
    From https://stackoverflow.com/questions/60355038/using-cpp-maps-with-array-values-in-cython
    """
    cdef string map_key
    cdef vector[float] map_val
    cdef cpair[string, vector[float]] map_element
    cdef cmap[string, vector[float]] my_map
    for key,val in the_dict.items():
        map_key = key
        map_val = val  # list values will be copied to C++ vector
        map_element = (map_key, map_val)
        my_map.insert(map_element)
    return my_map


cdef unsigned char* to_cstring_array(list_str):
    cdef int i
    cdef unsigned char* ret = <unsigned char*> PyMem_Malloc(len(list_str) * sizeof(unsigned char))
    if ret is NULL:
        raise MemoryError()

    for i in range(len(list_str)):
        ret[i] = list_str[i]
    return ret

def encrypt(model):
    cdef int buffer_len = 0
    cdef unsigned char* serialized_model

    serialized_model = serialize(dict_to_cmap(model), &buffer_len)
    if buffer_len <= 0:
        raise IndexError
    cdef bytes serialized_buffer = serialized_model[:buffer_len]
    ciphertext, iv, tag = cpp_encrypt_bytes(serialized_buffer, buffer_len)
    return ciphertext, iv, tag

def cpp_encrypt_bytes(model_data, data_len):
    cdef unsigned char** ciphertext = <unsigned char**> PyMem_Malloc(3 * sizeof(unsigned char*))
    if ciphertext is NULL:
        raise MemoryError()

    ciphertext[0] = <unsigned char*> PyMem_Malloc(data_len * sizeof(unsigned char))
    if ciphertext[0] is NULL:
        raise MemoryError()

    ciphertext[1] = <unsigned char*> PyMem_Malloc(12 * sizeof(unsigned char))
    if ciphertext[1] is NULL:
        raise MemoryError()

    ciphertext[2] = <unsigned char*> PyMem_Malloc(16 * sizeof(unsigned char))
    if ciphertext[2] is NULL:
        raise MemoryError()

    encrypt_bytes(model_data, data_len, &ciphertext)

    cdef bytes output = ciphertext[0][:data_len]
    cdef bytes iv = ciphertext[1][:12]
    cdef bytes tag = ciphertext[2][:16]
    
    PyMem_Free(ciphertext[0])
    PyMem_Free(ciphertext[1])
    PyMem_Free(ciphertext[2])
    PyMem_Free(ciphertext)

    return output, iv, tag

def decrypt(model_data, iv, tag, data_len):
    cdef unsigned char* plaintext = <unsigned char*> PyMem_Malloc(data_len * sizeof(unsigned char))
    cdef unsigned char* c_model_data = to_cstring_array(model_data)
    cdef unsigned char* c_iv = to_cstring_array(iv)
    cdef unsigned char* c_tag = to_cstring_array(tag)
    decrypt_bytes(c_model_data, c_iv, c_tag, data_len, &plaintext)

    # Cython automatically converts C++ map to Python dict
    cdef mapcpp[string, vector[float]] model 
    model = deserialize(plaintext)
    PyMem_Free(plaintext)
    PyMem_Free(c_model_data)
    PyMem_Free(c_iv)
    PyMem_Free(c_tag)
    return model
    
