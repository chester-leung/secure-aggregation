# cython: language_level=3

from libcpp.string cimport string
from libcpp.vector cimport vector
from libcpp.map cimport map as mapcpp
from ctypes import c_ubyte
from libcpp.map cimport map as cmap
from libcpp.pair cimport pair as cpair
from libcpp.vector cimport vector
#  from libc.stdlib cimport malloc, free
from cpython.mem cimport PyMem_Malloc, PyMem_Free
cimport numpy as np
import numpy as np
#  import threading

# TODO: Hold global interpreter lock upon PyMem_Malloc, PyMem_Free calls
# https://docs.python.org/3/c-api/memory.html
# Without holding the lock, these functions are not thread-safe

IV_LENGTH = 12
TAG_LENGTH = 16
np.import_array()

cdef extern from "../common/encryption/serialization.h":
    unsigned char* serialize(mapcpp[string, vector[float]] model, int* serialized_buffer_size)
    mapcpp[string, vector[float]] deserialize(unsigned char* serialized_buffer)

cdef extern from "../common/encryption/encrypt.h":
    void encrypt_bytes(unsigned char* model_data, size_t data_len, unsigned char** ciphertext)
    void decrypt_bytes(unsigned char* model_data, unsigned char* iv, unsigned char* tag, size_t data_len, unsigned char** text)

cdef extern from "numpy/arrayobject.h":
    void PyArray_ENABLEFLAGS(np.ndarray arr, int flags)

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
    print("kvah encryption start)")
    cdef int buffer_len = 0

    # FIXME: dict_to_cmap to translate dictionary to c++ readable map
    serialized_model = serialize(dict_to_cmap(model), &buffer_len)
    if buffer_len <= 0:
        raise IndexError
    #  cdef bytes serialized_buffer = serialized_model[:buffer_len]

    # Take ownership of C++ malloc'ed memory in Python
    cdef np.npy_intp shape[1] 
    shape[0] = <np.npy_intp> buffer_len
    cdef np.ndarray[np.uint8_t, ndim=1] py_serialized_model = np.PyArray_SimpleNewFromData(1, shape, np.NPY_UINT8, serialized_model)

    # Ensure that memory is freed
    PyArray_ENABLEFLAGS(py_serialized_model, np.NPY_OWNDATA)

    # Convert ndarray to Python bytes
    serialized_buffer = py_serialized_model.tobytes()
    ciphertext, iv, tag = cpp_encrypt_bytes(serialized_buffer, buffer_len)
    print("kvah encryption end)")
    return ciphertext, iv, tag

def cpp_encrypt_bytes(model_data, data_len):
    print('Beginning cpp encryption')
    cdef unsigned char* ciphertext = <unsigned char*> PyMem_Malloc((data_len + IV_LENGTH + TAG_LENGTH) * sizeof(unsigned char))
    if ciphertext is NULL:
        raise MemoryError()

    encrypt_bytes(model_data, data_len, &ciphertext)

    cdef bytes output = ciphertext[:data_len]
    cdef bytes iv = ciphertext[data_len:data_len + IV_LENGTH]
    cdef bytes tag = ciphertext[data_len + IV_LENGTH:data_len + IV_LENGTH + TAG_LENGTH]

    #  print("OPython output: ")
    #  for i in range(100):
    #      print(int(output[i]), end =" ")
    #  
    #  print("\nPython IV")
    #  for i in range(len(iv)):
    #      print(int(iv[i]), end =" ")
    #  
    #  print("\nPython tag")
    #  for i in range(len(tag)):
    #      print(int(tag[i]), end =" ")
    
    #  PyMem_Free(ciphertext[0])
    #  PyMem_Free(ciphertext[1])
    #  PyMem_Free(ciphertext[2])
    PyMem_Free(ciphertext)
    print("Finished cpp encryption")
    return output, iv, tag

def decrypt(model_data, iv, tag, data_len):
    print("kvah decryption start")
    cdef unsigned char* plaintext = <unsigned char*> PyMem_Malloc(data_len * sizeof(unsigned char))
    cdef unsigned char* c_model_data = to_cstring_array(model_data)
    cdef unsigned char* c_iv = to_cstring_array(iv)
    cdef unsigned char* c_tag = to_cstring_array(tag)
    decrypt_bytes(c_model_data, c_iv, c_tag, data_len, &plaintext)

    # Cython automatically converts C++ map to Python dict
    model = deserialize(plaintext)
    PyMem_Free(plaintext)
    PyMem_Free(c_model_data)
    PyMem_Free(c_iv)
    PyMem_Free(c_tag)
    print("kvah decryption end")
    return model
    
