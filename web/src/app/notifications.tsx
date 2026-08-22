import { useSyncExternalStore } from 'react';

type Notification = {
  id: number;
  message: string;
  tone: 'error' | 'success';
};

let current: Notification | null = null;
let nextId = 1;
const listeners = new Set<() => void>();

function publish(tone: Notification['tone'], message: string): void {
  current = { id: nextId, message, tone };
  nextId += 1;
  for (const listener of listeners) {
    listener();
  }
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function snapshot(): Notification | null {
  return current;
}

export function notifyFailure(message: string): void {
  publish('error', message);
}

export function notifySuccess(message: string): void {
  publish('success', message);
}

export function clearNotification(): void {
  if (current === null) {
    return;
  }
  current = null;
  for (const listener of listeners) {
    listener();
  }
}

function dismiss(id: number): void {
  if (current?.id !== id) {
    return;
  }
  clearNotification();
}

export function ToastViewport() {
  const notification = useSyncExternalStore(subscribe, snapshot, snapshot);
  if (notification === null) {
    return null;
  }
  return (
    <div
      className={`toast toast--${notification.tone}`}
      role={notification.tone === 'error' ? 'alert' : 'status'}
    >
      <span className="alert__glyph" aria-hidden="true">
        {notification.tone === 'error' ? '!' : '✓'}
      </span>
      <span>{notification.message}</span>
      <button
        type="button"
        className="toast__dismiss"
        aria-label="Dismiss notification"
        onClick={() => dismiss(notification.id)}
      >
        ×
      </button>
    </div>
  );
}
