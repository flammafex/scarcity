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
 */
import { generateId } from "./crypto.js";
// Define a generic handler type
export type EventHandler = (payload: IEvent) => void;

export interface IEvent {
  id?: string;
  type: string;
  payload: any;
  ts: number;
  source?: string;
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
    const wrapper: EventHandler = (evt) => {
      fn(evt);
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