// ShieldBreak_Mitigation.c

#include <ntifs.h>
#include <fltKernel.h>
#include <ntdddisk.h>
#include <ntstrsafe.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

PFLT_FILTER gFilterHandle = NULL;
BOOLEAN gProtectionActive = FALSE;
#define DRIVER_TAG 'SBM'

extern PULONG InitSafeBootMode;
volatile LONG gBlockedExploitAttempts = 0;


FLT_PREOP_CALLBACK_STATUS PreCreateMain(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (!gProtectionActive || Data->Iopb->MajorFunction != IRP_MJ_CREATE)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // Evaluate all dispositions we may not use All but since This is the Development Phase 
    // I will use what i need and keep them anyway if i needed to fix anything they would be there anyway
    ULONG createDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;
    BOOLEAN isCreateOrOverwrite = (createDisposition == FILE_CREATE ||
        createDisposition == FILE_OPEN_IF ||
        createDisposition == FILE_OVERWRITE_IF ||
        createDisposition == FILE_SUPERSEDE ||
        createDisposition == FILE_OVERWRITE);

    if (!isCreateOrOverwrite)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // I am using FLT_FILE_NAME_OPENED to prevent failure on unparsed reparse paths
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );

    if (!NT_SUCCESS(status) || nameInfo == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Check if target path falls within System32
    UNICODE_STRING system32Pattern = RTL_CONSTANT_STRING(L"*\\SYSTEM32\\*");
    UNICODE_STRING system32ShortPattern = RTL_CONSTANT_STRING(L"*\\SYS~*\\*");
    BOOLEAN isSystem32 = FsRtlIsNameInExpression(&system32Pattern, &nameInfo->Name, TRUE, NULL) ||
        FsRtlIsNameInExpression(&system32ShortPattern, &nameInfo->Name, TRUE, NULL);

    if (!isSystem32) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Identify SYSTEM execution context
    BOOLEAN isSystemCaller = PsIsSystemThread(PsGetCurrentThread()) ||
        PsGetCurrentProcessId() == (HANDLE)4;

    // Check for Alternate Data Stream
    UNICODE_STRING streamPattern = RTL_CONSTANT_STRING(L"*:*");
    BOOLEAN isStream = (nameInfo->Stream.Length > 0) ||
        FsRtlIsNameInExpression(&streamPattern, &nameInfo->Name, TRUE, NULL);

    // Stop SYSTEM callers from creating ADS in System32
    // This may Confuse you 
    // but it is Logical
    // If you did Pass ADS to Sys32 like how MSN did it 
    // You could handle it, System Could Handle it, Admins Could Handle it 
    // And even then System Callers even while updating DO NOT aquire a ADS to sys32 files in normal operations it overwrites them
    // i had Monitored for Hours on end while updating the OS when this was loaded 
    // The Update did not Fail and Windows Did not complain
    // and even if it does aquire ADS it would gracefully handle it anyway since it rarely adds files to the OS or Core of the OS itself 
    // But rather Overwrites it that is why i block all from grabbing and ADS to Sys32
    if (isSystemCaller && isStream) {
        FltReleaseFileNameInformation(nameInfo);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS PreCreate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext) {
    return PreCreateMain(Data, FltObjects, CompletionContext);
}



NTSTATUS FilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    if (gFilterHandle) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
    }

    return STATUS_SUCCESS;
}

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, PreCreate, NULL },
    { IRP_MJ_OPERATION_END }
};


CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),   // Size
    FLT_REGISTRATION_VERSION,   // Version
    0,                          // Flags
    NULL,                       // ContextRegistration (Must be NULL if unused! and it is unused LMAO) 
    Callbacks,                  // OperationRegistration
    FilterUnload,               // FilterUnloadCallback
    NULL,                       // InstanceSetup
    NULL                        // InstanceQueryTeardown
};
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltStartFiltering(gFilterHandle);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
        return status;
    }



    gProtectionActive = TRUE;
    return STATUS_SUCCESS;
}