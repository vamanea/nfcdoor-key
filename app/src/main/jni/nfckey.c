#include <stdint.h>
#include <jni.h>
#include <android/log.h>

#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, "NFCKey", __VA_ARGS__))
#define LOGW(...) ((void)__android_log_print(ANDROID_LOG_WARN, "NFCKey", __VA_ARGS__))


void Java_com_huawei_nfckey_utils_signCertificate(JNIEnv* env, jobject this, jbyteArray input, jbyteArray output)
{
    uint8_t buffer[100];
    jsize len = (*env)->GetArrayLength(env, input);
    LOGI("SIGN certificate %u", len);

    jbyte* data = (*env)->GetByteArrayElements(env, input, NULL);
    if (data != NULL) {
        memcpy(buffer, data, len);
        (*env)->ReleaseByteArrayElements(env, input, data, JNI_ABORT);
    }
    LOGI("Cert[0]=%02X", buffer[0]);



    //void* inputPtr = (*env)->GetDirectBufferAddress(env, input);
    //jlong inputLength = (*env)->GetDirectBufferCapacity(env, input);
/*
    void* hash = ...; // a pointer to the hash data
    int hashDataLength = ...;
    void** thumbnails = ...; // an array of pointers, each one points to thumbnail data
    int* thumbnailDataLengths = ...; // an array of ints, each one is the length of the thumbnail data with the same index

    jobject hashBuffer = env->NewDirectByteBuffer(hash, hashDataLength);
    env->SetObjectArrayElement(output, 0, hashBuffer);

    for (int i = 0; i < nThumbnails; i++)
        env->SetObjectArrayElement(output, i + 1, env->NewDirectByteBuffer(thumbnails[i], thumbnailDataLengths[i]));*/
}