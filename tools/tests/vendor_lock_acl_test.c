/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Verify vendor locks reject a writable native ACL without repairing it. */
#if defined(__MSYS__)
#define _POSIX_C_SOURCE 200809L
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <sys/cygwin.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <wchar.h>

static int failure(const char *reason)
{
    fprintf(stderr, "vendor_lock_acl_test: %s (errno=%d winerr=%lu)\n",
        reason, errno, (unsigned long)GetLastError());
    return 1;
}

static bool run_lock(const char *helper, const char *path, int expected)
{
    pid_t child = fork();
    if (child == 0) {
        execl(helper, helper, path, "0", "true", (char *)NULL);
        _exit(99);
    }
    int status = 0;
    return child > 0 && waitpid(child, &status, 0) == child &&
        WIFEXITED(status) && WEXITSTATUS(status) == expected;
}

/* Same explicit-ACE construction used by private_directory acceptance. */
static bool add_everyone_write(HANDLE file)
{
    PACL old_dacl = NULL, new_dacl = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    BYTE everyone[SECURITY_MAX_SID_SIZE];
    DWORD size = sizeof(everyone);
    bool ok = CreateWellKnownSid(WinWorldSid, NULL, everyone, &size) &&
        GetSecurityInfo(file, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
            NULL, NULL, &old_dacl, NULL, &descriptor) == ERROR_SUCCESS;
    EXPLICIT_ACCESSW entry = {0};
    entry.grfAccessPermissions = FILE_GENERIC_WRITE;
    entry.grfAccessMode = GRANT_ACCESS;
    entry.grfInheritance = NO_INHERITANCE;
    entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    entry.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    entry.Trustee.ptstrName = (LPWSTR)(void *)everyone;
    ok = ok && SetEntriesInAclW(1, &entry, old_dacl, &new_dacl) == ERROR_SUCCESS &&
        SetSecurityInfo(file, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION |
            PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, new_dacl,
            NULL) == ERROR_SUCCESS;
    if (new_dacl) LocalFree(new_dacl);
    if (descriptor) LocalFree(descriptor);
    return ok;
}

static LPWSTR acl_snapshot(HANDLE file)
{
    PSECURITY_DESCRIPTOR descriptor = NULL;
    LPWSTR sddl = NULL;
    SECURITY_INFORMATION fields = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    if (GetSecurityInfo(file, SE_FILE_OBJECT, fields, NULL, NULL, NULL, NULL,
            &descriptor) == ERROR_SUCCESS)
        (void)ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor, SDDL_REVISION_1, fields, &sddl, NULL);
    if (descriptor) LocalFree(descriptor);
    return sddl;
}

static int vendor_lock_acl_test(int argc, char **argv)
{
    if (argc != 3) return failure("expected helper and disposable lock path");
    if (!run_lock(argv[1], argv[2], 0)) return failure("private creation refused");
    wchar_t wide[32768];
    if (cygwin_conv_path(CCP_POSIX_TO_WIN_W, argv[2], wide, sizeof(wide)))
        return failure("path conversion failed");
    HANDLE file = CreateFileW(wide, READ_CONTROL | WRITE_DAC,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (file == INVALID_HANDLE_VALUE) return failure("fixture open failed");
    bool ok = add_everyone_write(file);
    LPWSTR before = ok ? acl_snapshot(file) : NULL;
    ok = before && run_lock(argv[1], argv[2], 75);
    LPWSTR after = acl_snapshot(file);
    ok = ok && after && wcscmp(before, after) == 0;
    if (before) LocalFree(before);
    if (after) LocalFree(after);
    bool closed = CloseHandle(file) != 0;
    if (!ok || !closed) return failure("writable ACL admitted or changed");
    puts("vendor_lock_acl_test: Everyone-write refusal and unchanged ACL PASS");
    return 0;
}
#endif
#include <stdio.h>
int main(int argc, char **argv)
{
#if defined(__MSYS__)
    return vendor_lock_acl_test(argc, argv);
#else
    (void)argc;
    (void)argv;
    fputs("vendor_lock_acl_test: MSYS native ACL fixture unavailable\n", stderr);
    return 77;
#endif
}
