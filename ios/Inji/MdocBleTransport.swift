import CoreBluetooth
import Foundation
import React

/**
 ISO/IEC 18013-5 §8.3.3.1.1 BLE transport, **mdoc peripheral server mode** — and nothing else.

 This is the only part of proximity presentment that cannot live in TypeScript: operating a GATT
 peripheral requires `CBPeripheralManager`, which is unreachable from JavaScript. Everything a
 verifier can actually observe — session keys, SessionTranscript, DeviceRequest parsing,
 DeviceResponse assembly, DeviceAuth — is implemented once in `shared/mdoc/presentment/` and
 shared with Android when it adopts the same contract. Deliberately kept dumb: no CBOR, no
 crypto, no ISO semantics. It advertises a UUID and moves opaque bytes.

 Two things here are load-bearing and easy to get wrong:

 - The advertised service UUID comes from JS, lifted out of the DeviceEngagement the QR already
   showed. Generating one here would make the reader look for a service that does not exist —
   the exact "GATT is not advertising" failure Credence diagnosed as Tap2iD error 115.
 - The Ident characteristic value is computed in TS (HMAC over EDeviceKeyBytes) and served here
   verbatim, so the two sides cannot drift.
 */
@objc(MdocBleTransport)
class MdocBleTransport: RCTEventEmitter {

    // ISO/IEC 18013-5:2021 Table 12 — characteristic UUIDs for mdoc peripheral server mode.
    // (Central client mode uses a different set; this wallet advertises peripheral server,
    // matching BleOptions key 0 = true in the engagement we generate.)
    private static let stateCharacteristicUUID = CBUUID(string: "00000001-A123-48CE-896B-4C76973373E6")
    private static let client2ServerCharacteristicUUID = CBUUID(string: "00000002-A123-48CE-896B-4C76973373E6")
    private static let server2ClientCharacteristicUUID = CBUUID(string: "00000003-A123-48CE-896B-4C76973373E6")
    private static let identCharacteristicUUID = CBUUID(string: "00000004-A123-48CE-896B-4C76973373E6")

    /// §8.3.3.1.1.2 State characteristic values.
    private static let stateStart: UInt8 = 0x01
    private static let stateEnd: UInt8 = 0x02

    /// §8.3.3.1.1.5 message framing: one leading byte per chunk.
    private static let chunkMore: UInt8 = 0x01
    private static let chunkLast: UInt8 = 0x00

    private static let eventConnected = "MdocBleConnected"
    private static let eventMessage = "MdocBleMessage"
    private static let eventDisconnected = "MdocBleDisconnected"
    private static let eventError = "MdocBleError"

    /// All CoreBluetooth work is serialised here; JS calls hop onto it before touching state.
    private let queue = DispatchQueue(label: "io.mosip.inji.mdoc.ble", qos: .userInitiated)

    private var peripheralManager: CBPeripheralManager?
    private var stateCharacteristic: CBMutableCharacteristic?
    private var client2ServerCharacteristic: CBMutableCharacteristic?
    private var server2ClientCharacteristic: CBMutableCharacteristic?
    private var identCharacteristic: CBMutableCharacteristic?

    private var serviceUUID: CBUUID?
    private var identValue: Data = Data()

    /// Accumulates inbound chunks until one arrives with the "last" framing byte.
    private var inboundBuffer = Data()

    /// Outbound chunks still to notify. CoreBluetooth applies backpressure by returning false
    /// from `updateValue`, at which point we pause until `peripheralManagerIsReady` fires.
    private var outboundChunks: [Data] = []
    private var subscribedCentral: CBCentral?

    private var startResolve: RCTPromiseResolveBlock?
    private var startReject: RCTPromiseRejectBlock?
    private var hasListeners = false

    // MARK: - RCTEventEmitter

    @objc
    override static func moduleName() -> String {
        return "MdocBleTransport"
    }

    override static func requiresMainQueueSetup() -> Bool {
        return false
    }

    @objc
    override func supportedEvents() -> [String]! {
        return [
            MdocBleTransport.eventConnected,
            MdocBleTransport.eventMessage,
            MdocBleTransport.eventDisconnected,
            MdocBleTransport.eventError,
        ]
    }

    override func startObserving() {
        hasListeners = true
    }

    override func stopObserving() {
        hasListeners = false
    }

    private func emit(_ name: String, _ body: [String: Any]) {
        guard hasListeners else { return }
        sendEvent(withName: name, body: body)
    }

    private func emitError(_ message: String) {
        log("error: %@", message)
        emit(MdocBleTransport.eventError, ["message": message])
    }

    /// Bring-up diagnostics. MTU, chunk counts and GATT transitions are only observable natively;
    /// everything else the session needs already reaches JS as events.
    /// Filter with: `xcrun simctl spawn booted log stream --predicate 'eventMessage CONTAINS "[MdocBle]"'`
    /// or Console.app on a device, and `idevicesyslog | grep MdocBle`.
    private func log(_ format: String, _ args: CVarArg...) {
        // NSLog is variadic C: a Swift [CVarArg] has to go through withVaList/NSLogv, or the
        // format specifiers read garbage off the stack instead of these arguments.
        withVaList(args) { NSLogv("[MdocBle] " + format, $0) }
    }

    // MARK: - JS API

    /// Opens the GATT server and begins advertising `serviceUuid`.
    ///
    /// Resolves once advertising is actually up — not merely requested — so JS does not paint a
    /// QR the reader cannot yet act on.
    @objc(start:resolver:rejecter:)
    func start(_ config: NSDictionary,
               resolver resolve: @escaping RCTPromiseResolveBlock,
               rejecter reject: @escaping RCTPromiseRejectBlock) {
        guard let uuidString = config["serviceUuid"] as? String,
              let identBase64 = config["identBase64"] as? String,
              let ident = Data(base64Encoded: identBase64) else {
            reject("E_MDOC_BLE_CONFIG", "serviceUuid and identBase64 are required", nil)
            return
        }

        queue.async { [weak self] in
            guard let self = self else { return }
            self.teardownLocked()
            self.serviceUUID = CBUUID(string: uuidString)
            self.identValue = ident
            self.startResolve = resolve
            self.startReject = reject
            // Advertising begins from peripheralManagerDidUpdateState once the radio is on.
            self.peripheralManager = CBPeripheralManager(delegate: self, queue: self.queue)
        }
    }

    /// Sends one complete message, chunked to the negotiated MTU.
    @objc(send:resolver:rejecter:)
    func send(_ base64: NSString,
              resolver resolve: @escaping RCTPromiseResolveBlock,
              rejecter reject: @escaping RCTPromiseRejectBlock) {
        guard let payload = Data(base64Encoded: base64 as String) else {
            reject("E_MDOC_BLE_SEND", "payload was not valid base64", nil)
            return
        }
        queue.async { [weak self] in
            guard let self = self else { return }
            guard let central = self.subscribedCentral,
                  self.server2ClientCharacteristic != nil else {
                reject("E_MDOC_BLE_SEND", "no reader is subscribed to Server2Client", nil)
                return
            }
            self.enqueueChunks(payload, for: central)
            self.flushOutbound()
            resolve(nil)
        }
    }

    /// Writes the §8.3.3.1.1.2 State characteristic (0x02 ends the session).
    @objc(sendState:resolver:rejecter:)
    func sendState(_ value: NSNumber,
                   resolver resolve: @escaping RCTPromiseResolveBlock,
                   rejecter reject: @escaping RCTPromiseRejectBlock) {
        queue.async { [weak self] in
            guard let self = self,
                  let manager = self.peripheralManager,
                  let characteristic = self.stateCharacteristic,
                  let central = self.subscribedCentral else {
                resolve(nil)
                return
            }
            let byte = Data([value.uint8Value])
            manager.updateValue(byte, for: characteristic, onSubscribedCentrals: [central])
            resolve(nil)
        }
    }

    @objc(stop:rejecter:)
    func stop(_ resolve: @escaping RCTPromiseResolveBlock,
              rejecter reject: @escaping RCTPromiseRejectBlock) {
        queue.async { [weak self] in
            self?.teardownLocked()
            resolve(nil)
        }
    }

    override func invalidate() {
        // Async rather than sync: `invalidate` arrives on the bridge thread, and a synchronous
        // hop would deadlock if it ever fired from our own queue. The block retains self until
        // the radio is released.
        queue.async { self.teardownLocked() }
        super.invalidate()
    }

    // MARK: - internals (all on `queue`)

    private func teardownLocked() {
        if let manager = peripheralManager {
            if manager.isAdvertising {
                manager.stopAdvertising()
            }
            manager.removeAllServices()
        }
        peripheralManager = nil
        stateCharacteristic = nil
        client2ServerCharacteristic = nil
        server2ClientCharacteristic = nil
        identCharacteristic = nil
        subscribedCentral = nil
        inboundBuffer.removeAll()
        outboundChunks.removeAll()
        serviceUUID = nil
        // A start still in flight must not leak its promise.
        if let reject = startReject {
            reject("E_MDOC_BLE_STOPPED", "BLE transport stopped before advertising began", nil)
        }
        startResolve = nil
        startReject = nil
    }

    private func publishServiceAndAdvertise() {
        guard let manager = peripheralManager, let serviceUUID = serviceUUID else { return }

        // ISO §8.3.3.1.1 specifies write-without-response for State and Client2Server, but readers
        // vary and some use write-with-response. Declaring both properties accepts either; a
        // reader that only ever uses one is unaffected.
        let state = CBMutableCharacteristic(
            type: MdocBleTransport.stateCharacteristicUUID,
            properties: [.notify, .write, .writeWithoutResponse],
            value: nil,
            permissions: [.writeable]
        )
        let client2Server = CBMutableCharacteristic(
            type: MdocBleTransport.client2ServerCharacteristicUUID,
            properties: [.write, .writeWithoutResponse],
            value: nil,
            permissions: [.writeable]
        )
        let server2Client = CBMutableCharacteristic(
            type: MdocBleTransport.server2ClientCharacteristicUUID,
            properties: [.notify],
            value: nil,
            permissions: [.readable]
        )
        // Ident is a fixed read: give it a static value so CoreBluetooth answers without a
        // delegate round-trip (§8.3.3.1.1.3 — readers use it to confirm they found the
        // peripheral the QR described).
        let ident = CBMutableCharacteristic(
            type: MdocBleTransport.identCharacteristicUUID,
            properties: [.read],
            value: identValue,
            permissions: [.readable]
        )

        let service = CBMutableService(type: serviceUUID, primary: true)
        service.characteristics = [state, client2Server, server2Client, ident]

        stateCharacteristic = state
        client2ServerCharacteristic = client2Server
        server2ClientCharacteristic = server2Client
        identCharacteristic = ident

        manager.removeAllServices()
        manager.add(service)
    }

    private func enqueueChunks(_ payload: Data, for central: CBCentral) {
        // `maximumUpdateValueLength` is the usable notification payload for this central; one
        // byte of it goes to the §8.3.3.1.1.5 framing prefix.
        let maxChunk = max(central.maximumUpdateValueLength - 1, 1)
        log("send %d bytes as %d chunk(s) (MTU payload %d)",
            payload.count,
            (payload.count + maxChunk - 1) / maxChunk,
            central.maximumUpdateValueLength)
        var offset = 0
        while offset < payload.count {
            let end = min(offset + maxChunk, payload.count)
            let isLast = end == payload.count
            var chunk = Data([isLast ? MdocBleTransport.chunkLast : MdocBleTransport.chunkMore])
            chunk.append(payload.subdata(in: offset..<end))
            outboundChunks.append(chunk)
            offset = end
        }
    }

    /// Drains the outbound queue until CoreBluetooth signals backpressure.
    private func flushOutbound() {
        guard let manager = peripheralManager,
              let characteristic = server2ClientCharacteristic,
              let central = subscribedCentral else { return }

        while let next = outboundChunks.first {
            let accepted = manager.updateValue(next, for: characteristic, onSubscribedCentrals: [central])
            if !accepted {
                // Queue is full; peripheralManagerIsReady(toUpdateSubscribers:) resumes us.
                return
            }
            outboundChunks.removeFirst()
        }
    }

    private func handleInbound(_ value: Data) {
        guard let first = value.first else { return }
        let body = value.dropFirst()
        inboundBuffer.append(body)

        switch first {
        case MdocBleTransport.chunkMore:
            return
        case MdocBleTransport.chunkLast:
            let complete = inboundBuffer
            inboundBuffer = Data()
            log("received complete message, %d bytes", complete.count)
            emit(MdocBleTransport.eventMessage, ["data": complete.base64EncodedString()])
        default:
            inboundBuffer = Data()
            emitError("Unexpected chunk framing byte 0x\(String(first, radix: 16)) on Client2Server")
        }
    }
}

// MARK: - CBPeripheralManagerDelegate

extension MdocBleTransport: CBPeripheralManagerDelegate {

    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        switch peripheral.state {
        case .poweredOn:
            publishServiceAndAdvertise()
        case .unauthorized:
            failStart("E_MDOC_BLE_UNAUTHORIZED", "Bluetooth permission was denied for this app.")
        case .poweredOff:
            failStart("E_MDOC_BLE_OFF", "Bluetooth is turned off.")
        case .unsupported:
            failStart("E_MDOC_BLE_UNSUPPORTED", "This device cannot act as a Bluetooth peripheral.")
        default:
            break
        }
    }

    func peripheralManager(_ peripheral: CBPeripheralManager,
                           didAdd service: CBService,
                           error: Error?) {
        if let error = error {
            failStart("E_MDOC_BLE_SERVICE", "Could not publish the GATT service: \(error.localizedDescription)")
            return
        }
        guard let serviceUUID = serviceUUID else { return }
        // 128-bit service UUIDs do not fit the 31-byte advertisement packet, so iOS moves them
        // into the scan response. Readers that actively scan (Tap2iD, Multipaz Verifier) still
        // discover them; a passive-only scanner would not.
        log("GATT service published, advertising %@", serviceUUID.uuidString)
        peripheral.startAdvertising([CBAdvertisementDataServiceUUIDsKey: [serviceUUID]])
    }

    func peripheralManagerDidStartAdvertising(_ peripheral: CBPeripheralManager, error: Error?) {
        if let error = error {
            failStart("E_MDOC_BLE_ADVERTISE", "Could not start advertising: \(error.localizedDescription)")
            return
        }
        log("advertising is live")
        startReject = nil
        startResolve?(nil)
        startResolve = nil
    }

    func peripheralManager(_ peripheral: CBPeripheralManager,
                           central: CBCentral,
                           didSubscribeTo characteristic: CBCharacteristic) {
        guard characteristic.uuid == MdocBleTransport.server2ClientCharacteristicUUID else { return }
        subscribedCentral = central
        log("reader subscribed to Server2Client (max notify payload %d bytes)",
            central.maximumUpdateValueLength)
        // Advertising past this point would invite a second reader into a session whose keys are
        // already bound to this one.
        if peripheral.isAdvertising {
            peripheral.stopAdvertising()
        }
        emit(MdocBleTransport.eventConnected, [:])
    }

    func peripheralManager(_ peripheral: CBPeripheralManager,
                           central: CBCentral,
                           didUnsubscribeFrom characteristic: CBCharacteristic) {
        guard characteristic.uuid == MdocBleTransport.server2ClientCharacteristicUUID else { return }
        subscribedCentral = nil
        outboundChunks.removeAll()
        emit(MdocBleTransport.eventDisconnected, [:])
    }

    func peripheralManager(_ peripheral: CBPeripheralManager,
                           didReceiveWrite requests: [CBATTRequest]) {
        for request in requests {
            guard let value = request.value else { continue }
            switch request.characteristic.uuid {
            case MdocBleTransport.client2ServerCharacteristicUUID:
                handleInbound(value)
            case MdocBleTransport.stateCharacteristicUUID:
                if value.first == MdocBleTransport.stateEnd {
                    emit(MdocBleTransport.eventDisconnected, [:])
                }
                // 0x01 (start) needs no action: the subscription already told us the reader is here.
            default:
                break
            }
        }
        // Writes are without-response, but CoreBluetooth still expects the queue to be drained.
        if let first = requests.first {
            peripheral.respond(to: first, withResult: .success)
        }
    }

    func peripheralManagerIsReady(toUpdateSubscribers peripheral: CBPeripheralManager) {
        flushOutbound()
    }

    private func failStart(_ code: String, _ message: String) {
        if let reject = startReject {
            startResolve = nil
            startReject = nil
            reject(code, message, nil)
        } else {
            emitError(message)
        }
    }
}
