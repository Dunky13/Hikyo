import { useEffect, useRef, type RefObject } from 'react';

/** Opens a native modal dialog and optionally puts focus on its first decision. */
export function useModalDialog(
  initialFocus?: RefObject<HTMLElement | null>,
): RefObject<HTMLDialogElement | null> {
  const dialog = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const element = dialog.current;
    if (element !== null && !element.open) {
      element.showModal();
    }
    initialFocus?.current?.focus();
    return () => {
      if (element?.open === true) {
        element.close();
      }
    };
  }, [initialFocus]);

  return dialog;
}
