package de.fhg.aisec.ids.idscp2.idscp_core.rat_registry

import de.fhg.aisec.ids.idscp2.idscp_core.drivers.RatProverDriver
import de.fhg.aisec.ids.idscp2.idscp_core.fsm.fsmListeners.RatProverFsmListener
import org.slf4j.LoggerFactory
import java.util.concurrent.ConcurrentHashMap

/**
 * A Rat Prover Driver Registry
 * The User can register Driver implementation instances and its configurations to the registry
 *
 *
 * The Idscpv2 protocol will select during the idscp handshake a Rat Prover mechanism and will
 * check for this RatProver in this registry
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
object RatProverDriverRegistry {
    private val LOG by lazy { LoggerFactory.getLogger(RatProverDriverRegistry::class.java) }

    /**
     * An inner static wrapper class, that wraps driver config and driver class
     */
    private class DriverWrapper<PC>(
            val driverFactory: (RatProverFsmListener) -> RatProverDriver<PC>,
            val driverConfig: PC?
    ) {
        fun getInstance(listener: RatProverFsmListener) = driverFactory.invoke(listener).also { d ->
            driverConfig?.let { d.setConfig(it) }
        }
    }

    private val drivers = ConcurrentHashMap<String, DriverWrapper<*>>()

    /**
     * Register Rat Prover driver and an optional configuration in the registry
     */
    fun <PC> registerDriver(
            instance: String,
            driverFactory: (RatProverFsmListener) -> RatProverDriver<PC>,
            driverConfig: PC?
    ) {
        drivers[instance] = DriverWrapper(driverFactory, driverConfig)
    }

    /**
     * Unregister the driver from the registry
     */
    fun unregisterDriver(instance: String) {
        drivers.remove(instance)
    }

    /**
     * To start a Rat Prover from the finite state machine
     *
     * First we check if the registry contains the RatProver instance, then we create a new
     * RatProverDriver from the driver wrapper that holds the corresponding RatProverDriver class.
     *
     * The finite state machine is registered as the communication partner for the RatProver.
     * The RatProver will be initialized with a configuration, if present. Then it is started.
     */
    fun startRatProverDriver(instance: String, listener: RatProverFsmListener): RatProverDriver<*>? {
        return drivers[instance]?.let { driverWrapper ->
            return try {
                driverWrapper.getInstance(listener).also { it.start() }
            } catch (e: Exception) {
                LOG.error("Error during RAT prover start", e)
                null
            }
        }
    }
}