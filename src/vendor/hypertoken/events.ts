/*
 * Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.
 *
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
 */
/*
 * core/events.ts
 *
 * Vendored from hypertoken-monorepo for Scarcity integration.
 */
import { generateId } from "./crypto.js";
// Define a generic handler type
export type EventHandler = (payload: any) => void;

export interface IEvent {
  id?: string;
  type: string;
  payload: any;
  ts: number;
  source?: any;
}

export class Emitter {
  // Map event names to sets of handlers
  protected _events: Record<string, Set<EventHandler>> = {};

  constructor() { 
    this._events = {}; 
  }
  
  on(type: string, fn: EventHandler): this {
    if (!this._events[type]) this._events[type] = new Set();
    this._events[type].add(fn);
    return this;
  }
  
  off(type: string, fn: EventHandler): this {
    if (this._events[type]) this._events[type].delete(fn);
    return this;
  }
  
  once(type: string, fn: EventHandler): this {
    const wrapper: EventHandler = (...args) => { 
      fn(...args); 
      this.off(type, wrapper); 
    };
    return this.on(type, wrapper);
  }
  
  emit(type: string, payload: any = {}): boolean {
    // Always create a structured event object
    const evt: IEvent = (payload && payload.type && payload.payload !== undefined)
      ? payload  // already an event object
      : {
          id: generateId(),
          type,
          payload,
          ts: Date.now()
        };

    // Dispatch to type-specific listeners
    if (this._events[type]) {
      for (const fn of this._events[type]) fn(evt);
    }
    // Dispatch to wildcard listeners
    if (this._events["*"]) {
      for (const fn of this._events["*"]) fn(evt);
    }
    return true;
  }
}

export interface EventRegistryOptions {
  storage?: Storage;
  maxEvents?: number;
  pruneStrategy?: "oldest" | "fifo";
}

/**
 * EventRegistry: Event logging and replay system with automatic pruning
 * Maintains a bounded log of events with configurable pruning strategies
 */
export class EventRegistry extends Emitter {
  name: string;
  events: IEvent[];
  private _sources: Set<Emitter>;
  private storage?: Storage;
  private _maxEvents: number;
  private _pruneStrategy: "oldest" | "fifo";

  /**
   * Create a new EventRegistry
   * @param name - Name of this registry
   * @param options - Configuration options
   */
  constructor(name: string = "session", { storage, maxEvents = 10000, pruneStrategy = "fifo" }: EventRegistryOptions = {}) {
    super();
    this.name = name;
    this.events = [];
    this._sources = new Set();
    this.storage = storage;
    this._maxEvents = maxEvents;
    this._pruneStrategy = pruneStrategy;
  }

  attach(source: Emitter, label: string | null = null): this {
    if (!source?.on) throw new Error("Source must be an Emitter.");
    if (this._sources.has(source)) return this;
    this._sources.add(source);

    const tag = label || source.constructor.name;
    source.on("*", (payload: any) => this.record("*", tag, payload));

    // Monkey-patch emit to intercept all events (common pattern in this architecture)
    const originalEmit = source.emit.bind(source);
    source.emit = (type: string, payload?: any) => {
      const result = originalEmit(type, payload);
      this.record(type, tag, payload);
      return result;
    };
    return this;
  }

  /**
   * Record an event to the registry
   * Automatically prunes old events if max limit is reached
   * @param type - Event type
   * @param source - Event source identifier
   * @param payload - Event payload data
   */
  record(type: string, source: string, payload: unknown): void {
    const evt: IEvent = {
      id: generateId(),
      type,
      source,
      payload,
      ts: Date.now()
    };
    this.events.push(evt);

    // Prune if we've exceeded max events
    if (this.events.length > this._maxEvents) {
      this._prune();
    }

    // Emit without wildcard to prevent infinite loops if registry is attached to itself
    if (this._events[type]) {
      for (const fn of this._events[type]) fn(evt);
    }
  }

  /**
   * Prune events based on configured strategy
   * @private
   */
  private _prune(): void {
    const excess = this.events.length - this._maxEvents;
    if (excess <= 0) return;

    if (this._pruneStrategy === "fifo" || this._pruneStrategy === "oldest") {
      // Both strategies remove from the beginning
      this.events.splice(0, excess);
      this.emit("registry:pruned", { count: excess, strategy: this._pruneStrategy });
    }
  }

  /**
   * Set maximum number of events to retain
   * @param max - Maximum event count
   * @throws Error if max is not a positive integer
   */
  setMaxEvents(max: number): this {
    if (max < 1 || !Number.isInteger(max)) {
      throw new Error(`Invalid max events: ${max}. Must be a positive integer.`);
    }
    this._maxEvents = max;
    if (this.events.length > this._maxEvents) {
      this._prune();
    }
    return this;
  }

  /**
   * Get current event count and maximum
   */
  getStats(): { current: number; max: number; strategy: string } {
    return {
      current: this.events.length,
      max: this._maxEvents,
      strategy: this._pruneStrategy
    };
  }

  last(n: number | null = null): IEvent[] { 
    return n ? this.events.slice(-n) : [...this.events]; 
  }
  
  filter(type: string): IEvent[] { 
    return this.events.filter(e => e.type === type); 
  }
  
  toJSON(): string { 
    return JSON.stringify({ name: this.name, count: this.events.length, events: this.events }, null, 2); 
  }

  saveLocal(key: string = "eventlog"): void {
    if (!this.storage?.setItem) return;
    this.storage.setItem(key, this.toJSON());
  }

  static loadLocal(key: string = "eventlog", { storage }: { storage?: Storage } = {}): EventRegistry | null {
    if (!storage?.getItem) return null;
    const raw = storage.getItem(key);
    if (!raw) return null;
    const data = JSON.parse(raw);
    const reg = new EventRegistry(data.name, { storage });
    reg.events = data.events || [];
    return reg;
  }

  clear(): void { this.events = []; }
}