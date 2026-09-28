# Phantom UI design context

## Visual direction

Phantom is a compact Windows desktop utility. Keep the existing restrained dark and light palettes, clear labels, and native WinForms interaction patterns. The dark palette uses RGB 30, 30, 34 for the form, RGB 42, 42, 48 for input surfaces, RGB 64, 64, 72 for borders, RGB 230, 230, 235 for text, and RGB 0, 122, 204 for the accent.

## Progress output

Keep the raw Log tab intact and place structured injection progress beside it. Each enabled DLL gets a method-specific, predeclared timeline with pending, running, succeeded, failed, warning, and skipped states. The visible count includes only planned milestones that were explicitly verified as succeeded. Optional stages appear only when requested. Put cleanup and recovery details in an expandable branch outside the planned-stage count; keep technical details expandable under their milestone.

Use the resolved process name, PID, and captured method in the batch summary. UI reporting is best-effort and must not affect injection behavior. Keep `CloseOnInject` behavior intact.
