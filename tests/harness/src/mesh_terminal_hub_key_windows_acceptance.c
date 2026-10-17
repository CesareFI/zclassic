/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: isolated native Windows terminal-hub key lifecycle and command edge.
 * This does not qualify a terminal session, transport, confinement or lead identity. */
#if defined(_WIN32)
#include "session/mesh_terminal_hub.h"
#include "command/native_command.h"
#include "native_mesh_terminal_hub.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "platform/rng.h"
#include "platform/windows_path.h"
#include <windows.h>
#include <aclapi.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(test) do { if (!(test)) { \
    fprintf(stderr, "hub_key_windows: FAIL line%d: %s (win32=%lu)\n", \
            __LINE__, #test, (unsigned long)GetLastError()); return false; \
} } while (0)

static void fixture_key(uint8_t key[32])
{
    for (size_t i = 0; i < 32; i++) key[i] = (uint8_t)(i * 17u);
}

static bool fixture_rng(void *opaque, uint8_t *out, size_t size)
{
    bool *success = opaque;
    if (size != 32) return false;
    fixture_key(out);
    return *success;
}

static bool fixture_init(const char *path, char fp[17], char why[160], bool success)
{
    struct rng_iface rng = {.fill = fixture_rng, .self = &success};
    rng_set_default(&rng);
    bool ok = mesh_terminal_hub_key_init(path, fp, why, 160);
    rng_reset_default();
    return ok;
}

static bool fixture_path(char out[4096], const char *root, const char *leaf)
{
    int n = snprintf(out, 4096, "%s/%s", root, leaf);
    return n > 0 && n < 4096;
}

static bool fixture_load_refused(const char *path)
{
    uint8_t key[32], zero[32] = {0};
    char why[160] = {0};
    memset(key, 0xa5, sizeof(key));
    REQUIRE(!mesh_terminal_hub_key_load(path, key, why, sizeof(why)));
    REQUIRE(why[0] && memcmp(key, zero, sizeof(key)) == 0);
    return true;
}

static bool fixture_store(const char *path, size_t size)
{
    uint8_t bytes[33] = {0};
    fixture_key(bytes);
    struct platform_private_file file;
    platform_private_file_init(&file);
    REQUIRE(platform_private_file_create(path, &file));
    bool ok = size <= sizeof(bytes) &&
        platform_private_file_validate_owner_private(&file) &&
        platform_private_file_write_at(&file, bytes, size, 0) &&
        platform_private_file_flush(&file);
    platform_private_file_close(&file);
    REQUIRE(ok);
    return true;
}

static bool fixture_positive(const char *path)
{
    char fp[17], expected_fp[17], why[160];
    uint8_t actual[32], expected[32];
    fixture_key(expected);
    REQUIRE(fixture_init(path, fp, why, true));
    REQUIRE(mesh_terminal_hub_key_load(path, actual, why, sizeof(why)));
    REQUIRE(memcmp(actual, expected, sizeof(actual)) == 0);
    mesh_terminal_hub_key_fingerprint(expected, expected_fp);
    REQUIRE(strcmp(fp, expected_fp) == 0 && strlen(fp) == 16);
    struct platform_private_file file;
    platform_private_file_init(&file);
    REQUIRE(platform_private_file_open_observation(path, &file));
    REQUIRE(platform_private_file_validate_owner_private(&file));
    platform_private_file_close(&file);
    REQUIRE(!platform_private_file_validate_owner_private(&file));
    memset(fp, 'x', sizeof(fp));
    REQUIRE(!fixture_init(path, fp, why, true));
    REQUIRE(fp[0] == '\0' && strstr(why, "already exists"));
    REQUIRE(mesh_terminal_hub_key_load(path, actual, why, sizeof(why)));
    REQUIRE(memcmp(actual, expected, sizeof(actual)) == 0);
    return true;
}

static bool fixture_extra_acl(const char *path, WELL_KNOWN_SID_TYPE kind)
{
    wchar_t wide[32768];
    REQUIRE(platform_windows_wide_path(path, wide));
    HANDLE file = CreateFileW(wide, READ_CONTROL | WRITE_DAC,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    REQUIRE(file != INVALID_HANDLE_VALUE);
    PSECURITY_DESCRIPTOR descriptor = NULL;
    PACL old_acl = NULL, next_acl = NULL;
    BYTE sid[SECURITY_MAX_SID_SIZE];
    DWORD sid_size = sizeof(sid);
    bool ok = GetSecurityInfo(file, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
        NULL, NULL, &old_acl, NULL, &descriptor) == ERROR_SUCCESS &&
        CreateWellKnownSid(kind, NULL, sid, &sid_size);
    EXPLICIT_ACCESSW entry = {0};
    entry.grfAccessPermissions = FILE_GENERIC_READ;
    entry.grfAccessMode = GRANT_ACCESS;
    entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    entry.Trustee.ptstrName = (LPWSTR)sid;
    ok = ok && SetEntriesInAclW(1, &entry, old_acl, &next_acl) == ERROR_SUCCESS &&
        SetSecurityInfo(file, SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            NULL, NULL, next_acl, NULL) == ERROR_SUCCESS;
    if (next_acl) LocalFree(next_acl);
    if (descriptor) LocalFree(descriptor);
    bool closed = CloseHandle(file) != 0;
    REQUIRE(ok && closed);
    return true;
}

static bool fixture_bad_acl(const char *root, const char *leaf,
                             WELL_KNOWN_SID_TYPE kind)
{
    char path[4096];
    REQUIRE(fixture_path(path, root, leaf) && fixture_store(path, 32));
    REQUIRE(fixture_extra_acl(path, kind));
    struct platform_private_file file;
    platform_private_file_init(&file);
    REQUIRE(platform_private_file_open_observation(path, &file));
    bool refused = !platform_private_file_validate_owner_private(&file);
    platform_private_file_close(&file);
    REQUIRE(refused && fixture_load_refused(path));
    REQUIRE(DeleteFileA(path));
    return true;
}

static bool fixture_inherited_acl(HANDLE file)
{
    PSECURITY_DESCRIPTOR descriptor = NULL;
    PACL acl = NULL;
    REQUIRE(GetSecurityInfo(file, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
        NULL, NULL, &acl, NULL, &descriptor) == ERROR_SUCCESS);
    ACL_SIZE_INFORMATION info = {0};
    bool inherited = false;
    bool ok = acl && GetAclInformation(acl, &info, sizeof(info), AclSizeInformation);
    for (DWORD i = 0; ok && i < info.AceCount; i++) {
        void *ace = NULL;
        ok = GetAce(acl, i, &ace) != 0;
        if (ok && (((ACE_HEADER *)ace)->AceFlags & INHERITED_ACE)) inherited = true;
    }
    LocalFree(descriptor);
    REQUIRE(ok && inherited);
    return true;
}

static bool fixture_inheritance_parent(const char *path)
{
    wchar_t wide[32768];
    REQUIRE(platform_private_directory_create(path));
    REQUIRE(platform_windows_wide_path(path, wide));
    HANDLE directory = CreateFileW(wide, READ_CONTROL | WRITE_DAC,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    REQUIRE(directory != INVALID_HANDLE_VALUE);
    PSECURITY_DESCRIPTOR descriptor = NULL;
    PACL acl = NULL;
    bool ok = GetSecurityInfo(directory, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
        NULL, NULL, &acl, NULL, &descriptor) == ERROR_SUCCESS;
    ACL_SIZE_INFORMATION info = {0};
    ok = ok && acl && GetAclInformation(acl, &info, sizeof(info), AclSizeInformation);
    for (DWORD i = 0; ok && i < info.AceCount; i++) {
        void *ace = NULL;
        ok = GetAce(acl, i, &ace) != 0;
        if (ok) ((ACE_HEADER *)ace)->AceFlags |= OBJECT_INHERIT_ACE;
    }
    ok = ok && SetSecurityInfo(directory, SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        NULL, NULL, acl, NULL) == ERROR_SUCCESS;
    if (descriptor) LocalFree(descriptor);
    bool closed = CloseHandle(directory) != 0;
    REQUIRE(ok && closed);
    return true;
}
static bool fixture_inherited(const char *root)
{
    char path[4096], parent[4096];
    wchar_t wide[32768];
    REQUIRE(fixture_path(parent, root, "inherit-parent"));
    REQUIRE(fixture_inheritance_parent(parent));
    REQUIRE(fixture_path(path, parent, "inherited.key"));
    REQUIRE(platform_windows_wide_path(path, wide));
    HANDLE file = CreateFileW(wide, GENERIC_WRITE | READ_CONTROL, 0, NULL,
        CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    REQUIRE(file != INVALID_HANDLE_VALUE);
    uint8_t bytes[32];
    fixture_key(bytes);
    DWORD written = 0;
    bool ok = WriteFile(file, bytes, sizeof(bytes), &written, NULL) &&
        written == sizeof(bytes) && fixture_inherited_acl(file);
    bool closed = CloseHandle(file) != 0;
    REQUIRE(ok && closed && fixture_load_refused(path));
    REQUIRE(DeleteFileW(wide));
    REQUIRE(RemoveDirectoryA(parent));
    return true;
}

static bool fixture_lengths(const char *root)
{
    const size_t sizes[] = {0, 31, 33};
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        char leaf[64], path[4096];
        REQUIRE(snprintf(leaf, sizeof(leaf), "length-%zu.key", sizes[i]) > 0);
        REQUIRE(fixture_path(path, root, leaf) && fixture_store(path, sizes[i]));
        REQUIRE(fixture_load_refused(path));
        REQUIRE(DeleteFileA(path));
    }
    REQUIRE(fixture_load_refused(NULL));
    char missing[4096];
    REQUIRE(fixture_path(missing, root, "missing.key"));
    REQUIRE(fixture_load_refused(missing));
    return true;
}

static bool fixture_rng_failure(const char *root)
{
    char path[4096], fp[17], why[160];
    REQUIRE(fixture_path(path, root, "rng-failure.key"));
    memset(fp, 'x', sizeof(fp));
    REQUIRE(!fixture_init(path, fp, why, false));
    REQUIRE(fp[0] == '\0' && strstr(why, "RNG"));
    REQUIRE(GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES &&
            GetLastError() == ERROR_FILE_NOT_FOUND);
    return true;
}

static bool fixture_command(const char *root)
{
    char path[4096], option[4128], why[160];
    REQUIRE(fixture_path(path, root, "command.key"));
    REQUIRE(snprintf(option, sizeof(option), "--key_file=%s", path) > 0);
    const char *init[] = {"serve", "--init-key", option};
    int rc = -1;
    REQUIRE(zcl_native_mesh_terminal_hub_try(init, 3, 0, &rc));
    REQUIRE(rc == ZCL_COMMAND_EXIT_OK);
    uint8_t key[32];
    REQUIRE(mesh_terminal_hub_key_load(path, key, why, sizeof(why)));
    REQUIRE(zcl_native_mesh_terminal_hub_try(init, 3, 0, &rc));
    REQUIRE(rc == ZCL_COMMAND_EXIT_INVALID);
    const char *serve[] = {"serve", option};
    REQUIRE(zcl_native_mesh_terminal_hub_try(serve, 2, 0, &rc));
    REQUIRE(rc == ZCL_COMMAND_EXIT_BLOCKED);
    const char *connect[] = {"connect", option};
    REQUIRE(zcl_native_mesh_terminal_hub_try(connect, 2, 0, &rc));
    REQUIRE(rc == ZCL_COMMAND_EXIT_BLOCKED);
    REQUIRE(DeleteFileA(path));
    return true;
}

#if defined(MESH_TERMINAL_HUB_KEY_GUID_REPARSE)
#include <winioctl.h>

struct fixture_guid_reparse {
    DWORD tag;
    WORD length;
    WORD reserved;
    GUID guid;
    BYTE data[1];
};
static_assert(offsetof(struct fixture_guid_reparse, data) == 24,
              "GUID reparse header width");

static bool fixture_guid_set(HANDLE file)
{
    struct fixture_guid_reparse data = {
        .tag = 0x00000042u, .length = 1,
        .guid = {0xa95ad832, 0xec9a, 0x4fd7,
                 {0x9e, 0x64, 0x12, 0x89, 0x6c, 0x2c, 0x4e, 0x3c}},
        .data = {0x5a}
    };
    OVERLAPPED operation = {0};
    operation.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    REQUIRE(operation.hEvent);
    DWORD transferred = 0;
    bool ok = DeviceIoControl(file, FSCTL_SET_REPARSE_POINT, &data,
        (DWORD)offsetof(struct fixture_guid_reparse, data) + data.length,
        NULL, 0, &transferred, &operation) != 0;
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    if (!ok && error == ERROR_IO_PENDING) {
        if (WaitForSingleObject(operation.hEvent, 5000) != WAIT_OBJECT_0) {
            (void)CancelIoEx(file, &operation);
            if (WaitForSingleObject(operation.hEvent, 5000) != WAIT_OBJECT_0) {
                /* Pending I/O owns the OVERLAPPED storage: do not return to
                 * an expired stack frame or claim cleanup of an unknown state. */
                fprintf(stderr, "hub_key_windows: pending reparse I/O cleanup unknown\n");
                ExitProcess(2);
            }
        }
        ok = GetOverlappedResult(file, &operation, &transferred, FALSE) != 0;
        error = ok ? ERROR_SUCCESS : GetLastError();
    }
    bool closed = CloseHandle(operation.hEvent) != 0;
    if (!ok) fprintf(stderr, "hub_key_windows: GUID reparse setup failed win32=%lu\n",
                      (unsigned long)error);
    REQUIRE(ok && closed);
    return true;
}

static bool fixture_guid_positive(struct platform_private_file *file)
{
    uint8_t expected[32], actual[32];
    fixture_key(expected);
    uint64_t size = 0;
    REQUIRE(platform_private_file_validate_owner_private(file));
    REQUIRE(platform_private_file_write_at(file, expected, sizeof(expected), 0));
    REQUIRE(platform_private_file_flush(file));
    REQUIRE(platform_private_file_size(file, &size) && size == sizeof(expected));
    REQUIRE(platform_private_file_read_at(file, actual, sizeof(actual), 0));
    REQUIRE(memcmp(expected, actual, sizeof(expected)) == 0);
    return true;
}

static bool fixture_guid_metadata(const char *path, struct platform_private_file *file,
                                   const struct platform_private_file_identity *identity)
{
    FILE_ATTRIBUTE_TAG_INFO retained = {0};
    REQUIRE(GetFileInformationByHandleEx((HANDLE)file->native,
        FileAttributeTagInfo, &retained, sizeof(retained)));
    REQUIRE(retained.ReparseTag == 0x42u &&
            (retained.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT));
    wchar_t wide[32768];
    REQUIRE(platform_windows_wide_path(path, wide));
    /* Match observation-open access/sharing/flags, without its attribute
     * rejection, so a sharing failure cannot stand in for reparse refusal. */
    HANDLE observation = CreateFileW(wide, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OVERLAPPED, NULL);
    REQUIRE(observation != INVALID_HANDLE_VALUE);
    BY_HANDLE_FILE_INFORMATION info = {0};
    bool ok = GetFileInformationByHandle(observation, &info) &&
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
        !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
        info.dwVolumeSerialNumber == identity->volume &&
        (((uint64_t)info.nFileIndexHigh << 32) | info.nFileIndexLow) == identity->file;
    bool closed = CloseHandle(observation) != 0;
    REQUIRE(ok && closed);
    return true;
}

static int fixture_reparse(const char *root, const char *target)
{
    (void)target;
    char path[4096];
    if (!fixture_path(path, root, "guid-reparse.key")) return 1;
    struct platform_private_file file;
    struct platform_private_file_identity identity;
    platform_private_file_init(&file);
    if (!platform_private_file_create(path, &file)) return 1;
    bool identified = platform_private_file_identity(&file, &identity);
    bool ok = identified && fixture_guid_positive(&file) &&
        fixture_guid_set((HANDLE)file.native) &&
        fixture_guid_metadata(path, &file, &identity) &&
        !platform_private_file_validate_owner_private(&file) &&
        fixture_load_refused(path);
    bool retired = identified &&
        platform_private_file_retire_if_identity(&file, path, &identity);
    platform_private_file_close(&file);
    if (!ok || !retired) {
        fprintf(stderr, "hub_key_windows: GUID reparse proof/identity cleanup failed path=%s\n", path);
        return 1;
    }
    puts("hub_key_windows: actual GUID tag/regular-file reparse metadata, matched read-open, retained/load refusal and exact cleanup PASS; file-symlink not tested");
    return 0;
}
#else
static int fixture_reparse(const char *root, const char *target)
{
    char path[4096];
    wchar_t wide[32768], target_wide[32768];
    if (!fixture_path(path, root, "link.key") ||
        !platform_windows_wide_path(path, wide) ||
        !platform_windows_wide_path(target, target_wide)) return 1;
    if (!CreateSymbolicLinkW(wide, target_wide, SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)) {
        fprintf(stderr, "hub_key_windows: REFUSE file-symlink fixture unavailable win32=%lu\n",
                (unsigned long)GetLastError());
        return 77;
    }
    bool ok = fixture_load_refused(path);
    bool removed = DeleteFileW(wide) != 0;
    return ok && removed ? 0 : 1;
}

#endif

static bool fixture_cases(const char *root, const char *positive)
{
    return fixture_positive(positive) &&
        fixture_bad_acl(root, "public.key", WinWorldSid) &&
        fixture_bad_acl(root, "extra.key", WinBuiltinAdministratorsSid) &&
        fixture_inherited(root) && fixture_lengths(root) &&
        fixture_rng_failure(root) && fixture_command(root);
}
int main(void)
{
    char cwd[3072], root[4096], positive[4096];
    DWORD size = GetCurrentDirectoryA(sizeof(cwd), cwd);
    if (!size || size >= sizeof(cwd) ||
        snprintf(root, sizeof(root), "%s/.cache/hub-key-%lu-%llu", cwd,
            (unsigned long)GetCurrentProcessId(),
            (unsigned long long)GetTickCount64()) <= 0 ||
        !platform_private_directory_create(root) ||
        !fixture_path(positive, root, "positive.key")) return 1;
    bool ok = fixture_cases(root, positive);
    int reparse = ok ? fixture_reparse(root, positive) : 1;
    if (!DeleteFileA(positive) || !RemoveDirectoryA(root)) {
        fprintf(stderr, "hub_key_windows: fixture cleanup failed root=%s\n", root);
        return 1;
    }
    if (!ok || reparse != 0) return reparse;
    puts("hub_key_windows: PASS private/exact key, fingerprint, no-clobber, ACL/length/reparse refusals, RNG cleanup, init-key edge; sessions remain refused");
    return 0;
}
#else
typedef int mesh_terminal_hub_key_windows_acceptance_not_built;
#endif
