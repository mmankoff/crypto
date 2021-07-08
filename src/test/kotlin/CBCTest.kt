
import org.hamcrest.CoreMatchers
import org.junit.Assert
import org.junit.Test
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class CBCTests {

    private val secureRandom = SecureRandom()

    /**
     * Generates a key with [this@generateKey] bits.
     */
    private fun Int.generateKey(): ByteArray {
        val result = ByteArray(this / 8)
        secureRandom.nextBytes(result)
        return result
    }

    /**
     * Generates an IV. The IV is always 128 bit long.
     */
    private fun generateIv(): ByteArray {
        val result = ByteArray(128 / 8)
        secureRandom.nextBytes(result)
        return result
    }

    /**
     * Generates a nonce for GCM mode. The nonce is always 96 bit long.
     */
    private fun generateNonce(): ByteArray {
        val result = ByteArray(96 / 8)
        secureRandom.nextBytes(result)
        return result
    }

    class Ciphertext(val ciphertext: ByteArray, val iv: ByteArray)

    /**
     * Encrypts the given [plaintext] with the given [key] under AES CBC with PKCS5 padding.
     *
     * This method generates a random IV.
     *
     * @return Ciphertext and IV
     */
    private fun encryptCbc(plaintext: ByteArray, key: ByteArray): Ciphertext {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val keySpec = SecretKeySpec(key, "AES")

        val iv = generateIv()
        val ivSpec = IvParameterSpec(iv)

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)

        val ciphertext = cipher.doFinal(plaintext)

        return Ciphertext(ciphertext, iv)
    }

    /**
     * Encrypts the given [plaintext] with the given [key] under AES GCM.
     *
     * This method generates a random nonce.
     *
     * @return Ciphertext and nonce
     */
    private fun encryptGcm(plaintext: ByteArray, key: ByteArray): Ciphertext {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(key, "AES")

        val nonce = generateNonce()
        val gcmSpec = GCMParameterSpec(128, nonce) // 128 bit authentication tag

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)

        val ciphertext = cipher.doFinal(plaintext)

        return Ciphertext(ciphertext, nonce)
    }

    /**
     * Generates a HMAC for the given [data] with the given [key] using HMAC-SHA256.
     *
     * @returns HMAC
     */
    private fun createHmac(data: ByteArray, key: ByteArray): ByteArray {
        val keySpec = SecretKeySpec(key, "HmacSHA256")
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(keySpec)

        return mac.doFinal(data)
    }

    /**
     * Checks the HMAC for the given [data] and the given [key] to match the [expectedHmac].
     *
     * The HMAC comparison is done in a timing attack proof way.
     *
     * @return True if the HMAC matches, false otherwise.
     */
    private fun checkHmac(data: ByteArray, key: ByteArray, expectedHmac: ByteArray): Boolean {
        val hmac = createHmac(data, key)

        // Check for equality in a timing attack proof way
        if (hmac.size != expectedHmac.size) return false
        var result = 0
        for (i in hmac.indices) {
            result = result.or(hmac[i].toInt().xor(expectedHmac[i].toInt()))
        }

        return result == 0
    }

    /**
     * Decrypts the given [ciphertext] using the given [key] under AES CBC with PKCS5 padding.
     *
     * @return Plaintext
     */
    private fun decryptCbc(ciphertext: Ciphertext, key: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val keySpec = SecretKeySpec(key, "AES")
        val ivSpec = IvParameterSpec(ciphertext.iv)

        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)

        return cipher.doFinal(ciphertext.ciphertext)
    }

    /**
     * Decrypts the given [ciphertext] using the given [key] under AES GCM.
     *
     * @return Plaintext
     */
    private fun decryptGcm(ciphertext: Ciphertext, key: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(key, "AES")

        val gcmSpec = GCMParameterSpec(128, ciphertext.iv) // 128 bit authentication tag

        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)

        return cipher.doFinal(ciphertext.ciphertext)
    }
    /**
     * Uses AES CBC with PKCS5 padding and a SHA256 HMAC.
     *
     * If you use AES CBC mode, you have to protect it with a HMAC!
     */
    @Test fun testCbcAndHmac() {
        // Generate two keys: one for CBC, one for the HMAC
        val cbcKey = 256.generateKey()
        val hmacKey = 256.generateKey()

        val plaintext = "This is the CBC test"

        // Encrypt the plaintext using AES CBC, the IV is generated automatically
        val ciphertext = encryptCbc(plaintext.toByteArray(), cbcKey)
        val hmac = createHmac(ciphertext.iv + ciphertext.ciphertext, hmacKey)

        // Now send the IV, the ciphertext and the HMAC over wire, or store it somewhere. It doesn't contain any secret information.

        // Before decrypting, check the HMAC. If it doesn't match, someone has tampered the data!
        if (!checkHmac(ciphertext.iv + ciphertext.ciphertext, hmacKey, hmac)) throw IllegalStateException("HMAC failed")
        // Decrypt the ciphertext. The decrypt message uses the IV which is stored in the ciphertext object
        val decrypted = String(decryptCbc(ciphertext, cbcKey), Charsets.UTF_8)

        Assert.assertThat(decrypted, CoreMatchers.equalTo(plaintext))

    }

    /**
     * Uses AES GCM.
     */
    @Test fun testGcm() {
        // GCM only needs one key. If you can use GCM, prefer that over CBC + HMAC
        val key = 256.generateKey()
        val plaintext = "This is the GCM test"

        // GCM uses a nonce. The encrypt message uses a random nonce. NEVER REUSE A NONCE!
        val ciphertext = encryptGcm(plaintext.toByteArray(), key)

        val decrypted = String(decryptGcm(ciphertext, key), Charsets.UTF_8)

        Assert.assertThat(decrypted, CoreMatchers.equalTo(plaintext))

        println(decrypted)
    }
}
