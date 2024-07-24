/*-
 * ========================LICENSE_START=================================
 * idscp2-core
 * %%
 * Copyright (C) 2021 Fraunhofer AISEC
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * =========================LICENSE_END==================================
 */
package de.fhg.aisec.ids.idscp2.defaultdrivers.securechannel.tls13.client

import java.io.DataInputStream
import java.io.EOFException
import java.io.InputStream
import java.net.SocketTimeoutException

/**
 * A simple Listener thread that listens to an input stream and notifies a listener
 * when new data has been received
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class InputListenerThread(val name: String, inputStream: InputStream, private var listener: DataAvailableListener) {
    private val dataInputStream: DataInputStream = DataInputStream(inputStream)

    @Volatile
    var running = true
        private set

    fun start() {
        Thread.ofVirtual().name(name).start {
            var buf: ByteArray
            while (running) {
                try {
                    // first read the length
                    val len = dataInputStream.readInt()
                    buf = ByteArray(len)
                    // then read the data
                    dataInputStream.readFully(buf, 0, len)
                    // provide to listener
                    listener.onMessage(buf)
                } catch (ignore: SocketTimeoutException) {
                    // timeout to catch safeStop() call
                } catch (e: EOFException) {
                    running = false
                    listener.onClose()
                } catch (e: Exception) {
                    running = false
                    listener.onError(e)
                }
            }
            try {
                dataInputStream.close()
            } catch (ignore: Exception) {
            }
        }
    }

    fun safeStop() {
        running = false
    }
}
