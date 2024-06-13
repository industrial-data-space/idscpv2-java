/*-
 * ========================LICENSE_START=================================
 * camel-idscp2
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
package de.fhg.aisec.ids.camel.idscp2

/**
 * A wrapped, synchronized HashMap counting the number of references to its values.
 * When all references are released, releaseFunction will be called to finalize the freed value.
 *
 * @author Michael Lux <michael.lux@aisec.fraunhofer.de>
 *
 * @param releaseFunction The function used to finalize elements without remaining references.
 */
class RefCountingHashMap<K, V>(private val releaseFunction: (V) -> Unit) {
    private val map = HashMap<K, Pair<Int, V>>()

    /**
     * Increments the reference count of an existing element
     * or inserts the element newly created by mappingFunction with reference count 1.
     *
     * @param key The key of the element to be retrieved (w. increased reference count)
     * or created with reference count 1.
     * @param mappingFunction The function to create the element if it doesn't exist
     */
    @Synchronized
    fun computeIfAbsent(key: K, mappingFunction: (K) -> V): V = map[key]?.let {
        map[key] = Pair(it.first + 1, it.second)
        it.second
    } ?: let {
        val value = mappingFunction(key)
        map[key] = Pair(1, value)
        value
    }

    /**
     * Decrements the reference count of an existing element,
     * deleting it and finalizing it using releaseFunction if reference count becomes zero.
     *
     * @param key Key of the element to be released
     */
    @Synchronized
    fun release(key: K) {
        map[key]?.let {
            if (it.first == 1) {
                releaseFunction(it.second)
                map.remove(key)
            } else {
                map[key] = Pair(it.first - 1, it.second)
            }
        }
    }

    /**
     * Removes an existing element, finalizing it using releaseFunction.
     *
     * @param key Key of the element to be removed
     */
    @Synchronized
    fun remove(key: K) {
        map[key]?.let {
            releaseFunction(it.second)
            map.remove(key)
        }
    }

    /**
     * Frees all resources (using releaseFunction) and clears the map.
     *
     * @param parallel Whether to use parallelStream() (default) or just stream() for iteration
     */
    @Synchronized
    fun freeAll(parallel: Boolean = true) {
        map.values.let { if (parallel) it.parallelStream() else it.stream() }
            .forEach { releaseFunction(it.second) }
        map.clear()
    }
}
