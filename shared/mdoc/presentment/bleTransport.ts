/**
 * The one platform boundary in the presentment stack.
 *
 * Everything above this file is common TypeScript. Everything below it is a per-platform native
 * module that does nothing but move bytes: advertise a GATT service, accept a connection, and
 * carry whole messages in each direction. No CBOR, no crypto, no ISO logic lives natively — that
 * is what keeps the protocol implementation shared, and what keeps the native surface small
 * enough to be reviewable.
 *
 * JavaScript cannot operate a GATT peripheral: `CBPeripheralManager` (iOS) and
 * `BluetoothGattServer` (Android) are reachable only from native code, and no maintained React
 * Native package exposes peripheral mode. So this shim is unavoidable — but it is the *whole* of
 * what is unavoidable.
 *
 * ## Division of responsibility
 *
 * Native owns MTU negotiation and the ISO 18013-5 §8.3.3.1.1.5 chunk framing (one leading byte
 * per chunk: `0x01` more-follows, `0x00` last). That framing is a function of the negotiated MTU
 * and of GATT write timing, both of which only native can see, and keeping it there means the
 * bridge carries one event per *message* rather than one per chunk — a ~100 KB response is a
 * single event instead of several hundred round trips.
 *
 * TypeScript owns everything a verifier can observe: session keys, SessionTranscript,
 * DeviceRequest parsing, DeviceResponse assembly and DeviceAuth.
 *
 * ## Android
 *
 * Deliberately not wired. Android has a working Multipaz-based native presenter today and is out
 * of scope for this change; {@link isMdocBleTransportAvailable} reports false there, so the
 * existing Android path is untouched. When Android does adopt this layer it implements the same
 * native contract and everything above keeps working unchanged.
 */

import {Buffer} from 'buffer';
import {
  EmitterSubscription,
  NativeEventEmitter,
  NativeModules,
  Platform,
} from 'react-native';

/** Native module name, identical on every platform that implements this contract. */
const NATIVE_MODULE_NAME = 'MdocBleTransport';

export const MDOC_BLE_EVENT_CONNECTED = 'MdocBleConnected';
export const MDOC_BLE_EVENT_MESSAGE = 'MdocBleMessage';
export const MDOC_BLE_EVENT_DISCONNECTED = 'MdocBleDisconnected';
export const MDOC_BLE_EVENT_ERROR = 'MdocBleError';

interface MdocBleNativeModule {
  /**
   * Starts advertising `serviceUuid` and opens the GATT server.
   *
   * `identBase64` is the ISO §8.3.3.1.1.3 Ident characteristic value (16 bytes), computed in TS
   * from EDeviceKeyBytes — native serves it verbatim and never derives it.
   */
  start(config: {serviceUuid: string; identBase64: string}): Promise<void>;
  /** Sends one complete message, chunked natively across Server2Client notifications. */
  send(base64: string): Promise<void>;
  /** Writes the §8.3.3.1.1.2 State characteristic value (0x02 = session termination). */
  sendState(value: number): Promise<void>;
  /** Stops advertising, drops the connection, and releases the peripheral. */
  stop(): Promise<void>;
  addListener(eventName: string): void;
  removeListeners(count: number): void;
}

function nativeModule(): MdocBleNativeModule | undefined {
  return (NativeModules as Record<string, MdocBleNativeModule | undefined>)[
    NATIVE_MODULE_NAME
  ];
}

/**
 * True when this build can run a TS-driven proximity session.
 *
 * iOS-only by design while Android keeps its Multipaz presenter — see the module note above.
 */
export function isMdocBleTransportAvailable(): boolean {
  return Platform.OS === 'ios' && !!nativeModule();
}

export interface MdocBleTransportCallbacks {
  onConnected: () => void;
  onMessage: (message: Uint8Array) => void;
  onDisconnected: () => void;
  onError: (error: Error) => void;
}

/** Formats a 16-byte big-endian UUID as the canonical 8-4-4-4-12 string CoreBluetooth wants. */
export function uuidBytesToString(uuid: Uint8Array): string {
  if (uuid.length !== 16) {
    throw new Error(`BLE service UUID must be 16 bytes, got ${uuid.length}`);
  }
  const hex = Array.from(uuid, b => b.toString(16).padStart(2, '0')).join('');
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ]
    .join('-')
    .toUpperCase();
}

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

function fromBase64(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, 'base64'));
}

/**
 * Thin lifetime wrapper around the native module.
 *
 * Subscriptions are torn down in {@link stop} so a cancelled session cannot deliver a late
 * message into an already-finished presentment — that would otherwise surface as a response
 * signed against the wrong SessionTranscript.
 */
export class MdocBleTransport {
  private subscriptions: EmitterSubscription[] = [];
  private stopped = false;

  private constructor(
    private readonly native: MdocBleNativeModule,
    private readonly emitter: NativeEventEmitter,
  ) {}

  static create(): MdocBleTransport {
    const native = nativeModule();
    if (!native) {
      throw new Error(
        `${NATIVE_MODULE_NAME} native module is not registered in this build — ` +
          'mdoc proximity presentment cannot advertise over BLE.',
      );
    }
    return new MdocBleTransport(
      native,
      new NativeEventEmitter(native as never),
    );
  }

  async start(
    serviceUuid: Uint8Array,
    ident: Uint8Array,
    callbacks: MdocBleTransportCallbacks,
  ): Promise<void> {
    this.subscriptions.push(
      this.emitter.addListener(MDOC_BLE_EVENT_CONNECTED, () => {
        if (!this.stopped) {
          callbacks.onConnected();
        }
      }),
      this.emitter.addListener(MDOC_BLE_EVENT_MESSAGE, (event: unknown) => {
        if (this.stopped) {
          return;
        }
        const base64 = (event as {data?: string} | undefined)?.data;
        if (typeof base64 !== 'string') {
          callbacks.onError(
            new Error('BLE message event carried no base64 payload'),
          );
          return;
        }
        callbacks.onMessage(fromBase64(base64));
      }),
      this.emitter.addListener(MDOC_BLE_EVENT_DISCONNECTED, () => {
        if (!this.stopped) {
          callbacks.onDisconnected();
        }
      }),
      this.emitter.addListener(MDOC_BLE_EVENT_ERROR, (event: unknown) => {
        if (this.stopped) {
          return;
        }
        const message =
          (event as {message?: string} | undefined)?.message ??
          'unknown BLE transport error';
        callbacks.onError(new Error(message));
      }),
    );

    await this.native.start({
      serviceUuid: uuidBytesToString(serviceUuid),
      identBase64: toBase64(ident),
    });
  }

  async send(message: Uint8Array): Promise<void> {
    await this.native.send(toBase64(message));
  }

  /** ISO §8.3.3.1.1.2 State characteristic: 0x02 signals end of session. */
  async sendSessionTermination(): Promise<void> {
    try {
      await this.native.sendState(0x02);
    } catch {
      // The reader may already be gone; termination is advisory and must not mask a real error.
    }
  }

  async stop(): Promise<void> {
    this.stopped = true;
    for (const sub of this.subscriptions) {
      sub.remove();
    }
    this.subscriptions = [];
    try {
      await this.native.stop();
    } catch {
      // Best-effort teardown: the peripheral may already be released.
    }
  }
}
