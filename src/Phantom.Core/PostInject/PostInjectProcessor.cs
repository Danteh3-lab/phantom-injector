using Phantom.Core.Injection;
using Phantom.Core.Native;

namespace Phantom.Core.PostInject;

/// <summary>
/// Applies the post-injection options (PE header erase, module hiding)
/// uniformly across every injection method.
/// </summary>
public static class PostInjectProcessor
{
    private readonly record struct EraseOutcome(
        bool Succeeded, string? Failure, bool RollbackFailed, bool ProtectionRestoreFailed)
    {
        public bool CanContinueWithHide => !RollbackFailed && !ProtectionRestoreFailed;
    }

    private const uint Access =
        NativeConstants.PROCESS_QUERY_INFORMATION |
        NativeConstants.PROCESS_VM_OPERATION |
        NativeConstants.PROCESS_VM_READ |
        NativeConstants.PROCESS_VM_WRITE |
        NativeConstants.PROCESS_CREATE_THREAD |
        NativeConstants.SYNCHRONIZE;

    /// <summary>
    /// Runs the requested post-injection steps. Returns <c>null</c> when every
    /// requested step succeeded, otherwise a description of what failed.
    /// </summary>
    public static string? Apply(uint pid, IntPtr moduleBase, InjectionOptions options)
    {
        if (moduleBase == IntPtr.Zero)
        {
            ReportConfiguredSteps(options, "Module base is unknown.");
            return "post-inject skipped: module base unknown.";
        }

        options.ReportProgress("postinject-access", "Open post-inject access", InjectionProgressStatus.Running,
            "Verifying access before changing the mapped image or loader lists.");
        var preflight = TargetPreflight.Check(pid, Access);
        if (preflight.ProbeError is not null)
        {
            options.ReportProgress("postinject-access", "Open post-inject access", InjectionProgressStatus.Failed, preflight.ProbeError);
            ReportConfiguredSteps(options, preflight.ProbeError);
            return "post-inject failed: " + preflight.ProbeError;
        }
        if (!preflight.Opened)
        {
            var detail = $"NtOpenProcess - {NtStatus.Describe(preflight.OpenStatus)}";
            options.ReportProgress("postinject-access", "Open post-inject access", InjectionProgressStatus.Failed, detail);
            ReportConfiguredSteps(options, detail);
            return $"post-inject failed: NtOpenProcess - {NtStatus.Describe(preflight.OpenStatus)}";
        }
        if (!preflight.RightsQueried)
        {
            var detail = $"Handle rights could not be verified ({NtStatus.Describe(preflight.QueryStatus)}).";
            options.ReportProgress("postinject-access", "Open post-inject access", InjectionProgressStatus.Failed, detail);
            ReportConfiguredSteps(options, detail);
            return $"post-inject failed: handle rights could not be verified ({NtStatus.Describe(preflight.QueryStatus)}).";
        }
        if (preflight.Missing.Length > 0)
        {
            var detail = "Required process rights are missing: " + string.Join(", ", preflight.Missing);
            options.ReportProgress("postinject-access", "Open post-inject access", InjectionProgressStatus.Failed, detail);
            ReportConfiguredSteps(options, detail);
            return $"post-inject failed: required process rights are missing ({string.Join(", ", preflight.Missing)}).";
        }

        using var target = preflight.Target;
        if (target is null)
        {
            options.ReportProgress("postinject-access", "Open post-inject access", InjectionProgressStatus.Failed,
                "Target process identity could not be retained.");
            ReportConfiguredSteps(options, "Target process identity could not be retained.");
            return "post-inject failed: target process identity could not be retained.";
        }

        options.ReportProgress("postinject-access", "Open post-inject access", InjectionProgressStatus.Succeeded,
            "Target access and identity verified.");

        using var targetScope = target.EnterScope();
        return Apply(target, moduleBase, options);
    }

    internal static string? Apply(TargetProcessIdentity target, IntPtr moduleBase, InjectionOptions options)
    {
        if (moduleBase == IntPtr.Zero)
        {
            ReportConfiguredSteps(options, "Module base is unknown.");
            return "post-inject skipped: module base unknown.";
        }

        IntPtr hProcess;
        {
            options.ReportProgress("postinject-access", "Open post-inject access", InjectionProgressStatus.Running,
                "Opening a verified handle for post-inject work.");
            try
            {
                hProcess = target.OpenVerifiedHandle(Access);
            }
            catch (Exception ex)
            {
                options.ReportProgress("postinject-access", "Open post-inject access", InjectionProgressStatus.Failed, ex.Message);
                ReportConfiguredSteps(options, ex.Message);
                return "post-inject failed: " + ex.Message;
            }
        }

        try
        {
            options.ReportProgress("postinject-access", "Open post-inject access", InjectionProgressStatus.Succeeded,
                "Verified target handle opened for post-inject work.");
            var failures = new List<string>();
            EraseOutcome? eraseOutcome = null;

            if (options.ErasePeHeaders)
            {
                options.ReportProgress("postinject-erase", "Erase PE headers", InjectionProgressStatus.Running,
                    "Saving the original header page before attempting a verified zeroing operation.");
                eraseOutcome = EraseHeaders(hProcess, moduleBase);
                if (!eraseOutcome.Value.Succeeded)
                {
                    failures.Add("erase PE headers (" + eraseOutcome.Value.Failure + ")");
                    options.ReportProgress("postinject-erase", "Erase PE headers",
                        eraseOutcome.Value.CanContinueWithHide ? InjectionProgressStatus.Warning : InjectionProgressStatus.Failed,
                        eraseOutcome.Value.CanContinueWithHide
                            ? "Header erase did not complete; rollback and protections were verified, so hiding can continue."
                            : "Header erase failed and rollback or protection recovery was not verified.",
                        eraseOutcome.Value.Failure);
                }
                else
                    options.ReportProgress("postinject-erase", "Erase PE headers", InjectionProgressStatus.Succeeded,
                        "Header page was zeroed and verified; original protection restored.");
            }
            else
                options.ReportProgress("postinject-erase", "Erase PE headers", InjectionProgressStatus.Skipped,
                    "Erase PE was not requested.");

            if (options.HideModule)
            {
                if (eraseOutcome.HasValue && !eraseOutcome.Value.CanContinueWithHide)
                {
                    var unsafeErase = eraseOutcome.Value;
                    var reasons = new List<string>();
                    if (unsafeErase.RollbackFailed)
                        reasons.Add("header rollback failed");
                    if (unsafeErase.ProtectionRestoreFailed)
                        reasons.Add("original page protection restoration failed");
                    failures.Add("hide module skipped because " + string.Join(" and ", reasons) + ".");
                    options.ReportProgress("postinject-hide", "Hide module", InjectionProgressStatus.Skipped,
                        "Skipped because header recovery was not verified.", string.Join(" and ", reasons));
                }
                else
                {
                    options.ReportProgress("postinject-hide", "Hide module", InjectionProgressStatus.Running,
                        "Unlinking the module under the target loader lock.");
                    // Post-inject steps must never turn a successful injection into a
                    // top-level error; convert any failure into a warning.
                    try
                    {
                        if (!LoaderLockUnlink.TryUnlink(target.Pid, hProcess, moduleBase, out var hideError, out var hashNote))
                        {
                            failures.Add("hide module (" + (hideError ?? "failed") + ")");
                            options.ReportProgress("postinject-hide", "Hide module", InjectionProgressStatus.Failed,
                                hideError ?? "Loader-list unlink failed.");
                        }
                        else if (hashNote is not null)
                        {
                            // Lists unlinked; hash-table cloaking skipped — warning only.
                            failures.Add("hide module hash (" + hashNote + ")");
                            options.ReportProgress("postinject-hide", "Hide module", InjectionProgressStatus.Warning,
                                "Loader lists were unlinked; hash-table unlink was skipped.", hashNote);
                        }
                        else
                            options.ReportProgress("postinject-hide", "Hide module", InjectionProgressStatus.Succeeded,
                                "Module was unlinked from the target loader lists.");
                    }
                    catch (Exception ex)
                    {
                        failures.Add("hide module (" + ex.Message + ")");
                        options.ReportProgress("postinject-hide", "Hide module", InjectionProgressStatus.Failed, ex.Message);
                    }
                }
            }
            else
                options.ReportProgress("postinject-hide", "Hide module", InjectionProgressStatus.Skipped,
                    "Hide Module was not requested.");

            return failures.Count == 0 ? null : "post-inject failed: " + string.Join(", ", failures);
        }
        finally
        {
            NativeMethods.CloseHandle(hProcess);
        }
    }

    private static void ReportConfiguredSteps(InjectionOptions options, string details)
    {
        options.ReportProgress("postinject-erase", "Erase PE headers", InjectionProgressStatus.Skipped,
            options.ErasePeHeaders ? "Skipped because post-inject access or module base was unavailable." :
            "Erase PE was not requested.", options.ErasePeHeaders ? details : null);
        options.ReportProgress("postinject-hide", "Hide module", InjectionProgressStatus.Skipped,
            options.HideModule ? "Skipped because post-inject access or module base was unavailable." :
            "Hide Module was not requested.", options.HideModule ? details : null);
    }

    private static EraseOutcome EraseHeaders(IntPtr hProcess, IntPtr moduleBase)
    {
        const int size = 0x1000;
        var backup = new byte[size];
        int readStatus;
        UIntPtr bytesRead;
        try
        {
            readStatus = DirectSyscalls.NtReadVirtualMemory(hProcess, moduleBase, backup, out bytesRead);
        }
        catch (Exception ex)
        {
            return new EraseOutcome(false, "could not capture the original 4096 bytes: " + ex.Message,
                RollbackFailed: false, ProtectionRestoreFailed: false);
        }

        if (readStatus != 0 || bytesRead.ToUInt64() != (ulong)size)
        {
            return new EraseOutcome(false,
                $"could not capture the original 4096 bytes (NTSTATUS 0x{readStatus:X8}, read {bytesRead.ToUInt64()}/{size} bytes)",
                RollbackFailed: false, ProtectionRestoreFailed: false);
        }

        var baseAddr = moduleBase;
        var region = (UIntPtr)size;
        uint oldProtect;
        int protectStatus;
        try
        {
            protectStatus = DirectSyscalls.NtProtectVirtualMemory(hProcess, ref baseAddr, ref region,
                NativeConstants.PAGE_READWRITE, out oldProtect);
        }
        catch (Exception ex)
        {
            return new EraseOutcome(false, "could not make headers writable: " + ex.Message,
                RollbackFailed: false, ProtectionRestoreFailed: false);
        }

        if (protectStatus != 0)
        {
            return new EraseOutcome(false, $"could not make headers writable (NTSTATUS 0x{protectStatus:X8})",
                RollbackFailed: false, ProtectionRestoreFailed: false);
        }

        string? eraseFailure = null;
        string? rollbackFailure = null;
        string? protectionFailure = null;
        try
        {
            var zeroStatus = DirectSyscalls.NtWriteVirtualMemory(hProcess, moduleBase, new byte[size], out var written);
            if (zeroStatus != 0 || written.ToUInt64() != (ulong)size)
            {
                eraseFailure = $"header erase failed (NTSTATUS 0x{zeroStatus:X8}, wrote {written.ToUInt64()}/{size} bytes)";
                rollbackFailure = TryRestoreHeaderBytes(hProcess, moduleBase, backup);
            }
            else
            {
                var zeroVerify = new byte[size];
                var verifyStatus = DirectSyscalls.NtReadVirtualMemory(hProcess, moduleBase, zeroVerify, out var verified);
                var hasNonzeroBytes = verifyStatus == 0 && verified.ToUInt64() == (ulong)size &&
                                      zeroVerify.Any(value => value != 0);
                if (verifyStatus != 0 || verified.ToUInt64() != (ulong)size || hasNonzeroBytes)
                {
                    var verificationResult = verifyStatus != 0 || verified.ToUInt64() != (ulong)size
                        ? $"NTSTATUS 0x{verifyStatus:X8}, read {verified.ToUInt64()}/{size} bytes"
                        : "readback contained nonzero bytes";
                    eraseFailure = "zeroed header verification failed (" + verificationResult + ")";
                    rollbackFailure = TryRestoreHeaderBytes(hProcess, moduleBase, backup);
                }
            }
        }
        catch (Exception ex)
        {
            eraseFailure = "header erase or verification threw an exception: " + ex.Message;
            rollbackFailure = TryRestoreHeaderBytes(hProcess, moduleBase, backup);
        }
        finally
        {
            try
            {
                var restoreBase = baseAddr;
                var restoreRegion = region;
                var restoreStatus = DirectSyscalls.NtProtectVirtualMemory(hProcess, ref restoreBase,
                    ref restoreRegion, oldProtect, out _);
                if (restoreStatus != 0)
                    protectionFailure = $"restoring the original protection failed (NTSTATUS 0x{restoreStatus:X8})";
            }
            catch (Exception ex)
            {
                protectionFailure = "restoring the original protection threw an exception: " + ex.Message;
            }
        }

        var rollbackFailed = eraseFailure is not null && rollbackFailure is not null;
        var protectionRestoreFailed = protectionFailure is not null;
        var failures = new List<string>();
        if (eraseFailure is not null)
        {
            failures.Add(eraseFailure);
            failures.Add(rollbackFailure is null
                ? "original header bytes were restored and verified"
                : "rollback failed: " + rollbackFailure);
        }

        if (protectionFailure is not null)
            failures.Add(eraseFailure is null
                ? "header erase completed, but " + protectionFailure
                : protectionFailure);

        if (failures.Count == 0)
            return new EraseOutcome(true, null, RollbackFailed: false, ProtectionRestoreFailed: false);

        return new EraseOutcome(false, string.Join("; ", failures), rollbackFailed, protectionRestoreFailed);
    }

    private static string? TryRestoreHeaderBytes(IntPtr hProcess, IntPtr moduleBase, byte[] backup)
    {
        try
        {
            var writeStatus = DirectSyscalls.NtWriteVirtualMemory(hProcess, moduleBase, backup, out var written);
            if (writeStatus != 0 || written.ToUInt64() != (ulong)backup.Length)
                return $"backup write failed (NTSTATUS 0x{writeStatus:X8}, wrote {written.ToUInt64()}/{backup.Length} bytes)";

            var verify = new byte[backup.Length];
            var readStatus = DirectSyscalls.NtReadVirtualMemory(hProcess, moduleBase, verify, out var read);
            if (readStatus != 0 || read.ToUInt64() != (ulong)backup.Length)
                return $"backup verification read failed (NTSTATUS 0x{readStatus:X8}, read {read.ToUInt64()}/{backup.Length} bytes)";

            return backup.AsSpan().SequenceEqual(verify)
                ? null
                : "backup verification found mismatched bytes";
        }
        catch (Exception ex)
        {
            return "backup restoration or verification threw an exception: " + ex.Message;
        }
    }
}
