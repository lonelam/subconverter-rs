/**
 * Copy text to the clipboard with a fallback for contexts where the
 * async Clipboard API is unavailable (non-HTTPS origins, older browsers).
 *
 * `navigator.clipboard` is undefined outside secure contexts, which made the
 * copy buttons crash with "Cannot read properties of undefined" (issue #33).
 */
export async function copyToClipboard(text: string): Promise<boolean> {
    if (typeof navigator !== 'undefined' && navigator.clipboard && window.isSecureContext) {
        try {
            await navigator.clipboard.writeText(text);
            return true;
        } catch {
            // fall through to the legacy path
        }
    }

    try {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        // Prevent scrolling and keep it invisible
        textarea.style.position = 'fixed';
        textarea.style.top = '0';
        textarea.style.left = '0';
        textarea.style.opacity = '0';
        textarea.setAttribute('readonly', '');
        document.body.appendChild(textarea);
        textarea.select();
        textarea.setSelectionRange(0, textarea.value.length);
        const succeeded = document.execCommand('copy');
        document.body.removeChild(textarea);
        return succeeded;
    } catch {
        return false;
    }
}
