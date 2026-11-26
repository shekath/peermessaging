package com.cipher.p2p

import com.cipher.p2p.crypto.Padding
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class PaddingTest {
    @Test fun roundTripsAndHidesLength() {
        for (n in listOf(0, 1, 159, 160, 511, 4000, 70000)) {
            val msg = ByteArray(n) { (it % 251 + 1).toByte() }
            val padded = Padding.pad(msg)
            assertArrayEquals(msg, Padding.unpad(padded))
            assert(padded.size > n)
        }
        assertEquals(Padding.pad(ByteArray(3)).size, Padding.pad(ByteArray(150)).size) // same bucket
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsTamperedPadding() { Padding.unpad(ByteArray(160)) }
}
