import { useLayoutEffect, useRef, useState, type RefObject } from 'react';

/**
 * useModalDialog opens a native `<dialog>` with `showModal()` and closes it on
 * unmount, optionally putting focus on the dialog's first decision.
 *
 * The platform gives a real focus trap, an inert document behind it, Escape and
 * the top layer — every part of which a hand-rolled `role="dialog"` has to
 * reimplement, and the focus trap is the part everyone gets wrong. The close on
 * unmount is what makes focus RESTORATION real: the platform returns focus to
 * the element that was focused before `showModal()` only when the dialog is
 * closed, and a dialog that is simply removed from the tree while open leaves a
 * keyboard user on `<body>`. Callers that want to be asked before closing keep
 * using `onCancel`; this only covers the unmount.
 */
export function useModalDialog(
  initialFocus?: RefObject<HTMLElement | null>,
): RefObject<HTMLDialogElement | null> {
  const dialog = useRef<HTMLDialogElement>(null);

  useLayoutEffect(() => {
    const element = dialog.current;
    if (element !== null && !element.open) {
      element.showModal();
    }
    initialFocus?.current?.focus();
    return () => {
      if (element !== null && element.open) {
        element.close();
      }
    };
  }, [initialFocus]);

  return dialog;
}

/**
 * useFeedback is the one (failure | done) status pair a surface shows after a
 * mutation: reporting a failure clears the last success and vice versa, so the
 * page never shows both "saved" and "refused" for the same act.
 */
export function useFeedback(failureText: (error: unknown) => string) {
  const [state, setState] = useState<{ failure: string | null; done: string | null }>({
    failure: null,
    done: null,
  });
  return {
    failure: state.failure,
    done: state.done,
    report: (error: unknown) => setState({ failure: failureText(error), done: null }),
    ok: (text: string) => setState({ failure: null, done: text }),
    clear: () => setState({ failure: null, done: null }),
  };
}
