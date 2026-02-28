const std = @import("std");
const utils = @import("utils.zig");
const win = @cImport(@cInclude("windows.h"));

// ============================================================================
// COM / CLR type definitions
// ============================================================================

pub const GUID = extern struct {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [8]u8,
};

pub const HRESULT = i32;

pub const SAFEARRAYBOUND = extern struct {
    c_elements: u32,
    l_lbound: i32,
};

pub const SAFEARRAY = extern struct {
    c_dims: u16,
    f_features: u16,
    cb_elements: u32,
    c_locks: u32,
    pv_data: ?*anyopaque,
    rgsabound: [1]SAFEARRAYBOUND,
};

/// VARIANT (COM automation) - 24 bytes on x64
pub const VARIANT = extern struct {
    vt: u16,
    w_reserved1: u16,
    w_reserved2: u16,
    w_reserved3: u16,
    data: usize, // pointer-sized union
    _pad: usize, // second qword of the union
};

const VT_EMPTY: u16 = 0;
const VT_UI1: u16 = 17;
const VT_BSTR: u16 = 8;
const VT_ARRAY: u16 = 0x2000;
const VT_VARIANT: u16 = 12;

const empty_variant = VARIANT{ .vt = VT_EMPTY, .w_reserved1 = 0, .w_reserved2 = 0, .w_reserved3 = 0, .data = 0, ._pad = 0 };

// --- GUID constants ---

const CLSID_CLR_META_HOST = GUID{
    .data1 = 0x9280188D,
    .data2 = 0x0E8E,
    .data3 = 0x4867,
    .data4 = .{ 0xB3, 0x0C, 0x7F, 0xA8, 0x38, 0x84, 0xE8, 0xDE },
};

const IID_ICLR_META_HOST = GUID{
    .data1 = 0xD332DB9E,
    .data2 = 0xB9B3,
    .data3 = 0x4125,
    .data4 = .{ 0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16 },
};

const CLSID_COR_RUNTIME_HOST = GUID{
    .data1 = 0xCB2F6723,
    .data2 = 0xAB3A,
    .data3 = 0x11D2,
    .data4 = .{ 0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E },
};

const IID_ICOR_RUNTIME_HOST = GUID{
    .data1 = 0xCB2F6722,
    .data2 = 0xAB3A,
    .data3 = 0x11D2,
    .data4 = .{ 0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E },
};

const IID_ICLR_RUNTIME_INFO = GUID{
    .data1 = 0xBD39D1D2,
    .data2 = 0xBA2F,
    .data3 = 0x486A,
    .data4 = .{ 0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91 },
};

const IID_APP_DOMAIN = GUID{
    .data1 = 0x05F696DC,
    .data2 = 0x2B29,
    .data3 = 0x3663,
    .data4 = .{ 0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13 },
};

// --- Function pointer types (loaded dynamically) ---

const FnCLRCreateInstance = *const fn (
    clsid: *const GUID,
    riid: *const GUID,
    pp_interface: *?*anyopaque,
) callconv(.c) HRESULT;

const FnSafeArrayCreate = *const fn (
    vt: u16,
    c_dims: u32,
    rgsabound: *SAFEARRAYBOUND,
) callconv(.c) ?*SAFEARRAY;

const FnSafeArrayAccessData = *const fn (
    psa: *SAFEARRAY,
    pp_data: *?*anyopaque,
) callconv(.c) HRESULT;

const FnSafeArrayUnaccessData = *const fn (
    psa: *SAFEARRAY,
) callconv(.c) HRESULT;

const FnSafeArrayDestroy = *const fn (
    psa: *SAFEARRAY,
) callconv(.c) HRESULT;

const FnSysAllocString = *const fn (
    psz: [*:0]const u16,
) callconv(.c) ?*u16;

// ============================================================================
// COM vtable access helpers
// ============================================================================

/// Read a function pointer from a COM vtable at a given slot index.
fn vtblSlot(comptime T: type, obj: *anyopaque, slot: usize) T {
    const vtbl_ptr: *const [*]const usize = @ptrCast(@alignCast(obj));
    const vtbl: [*]const usize = vtbl_ptr.*;
    return @ptrFromInt(vtbl[slot]);
}

/// Call IUnknown::Release on a COM pointer
fn releaseCom(punk: ?*anyopaque) void {
    if (punk) |p| {
        const release_fn = vtblSlot(*const fn (*anyopaque) callconv(.c) u32, p, 2);
        _ = release_fn(p);
    }
}

// ============================================================================
// SafeArray helpers
// ============================================================================

fn createSafeArrayFromBytes(
    buffer: []const u8,
    sa_create: FnSafeArrayCreate,
    sa_access: FnSafeArrayAccessData,
    sa_unaccess: FnSafeArrayUnaccessData,
) ?*SAFEARRAY {
    var bound = SAFEARRAYBOUND{ .c_elements = @intCast(buffer.len), .l_lbound = 0 };
    const sa = sa_create(VT_UI1, 1, &bound) orelse return null;

    var pv_data: ?*anyopaque = null;
    if (sa_access(sa, &pv_data) < 0) return sa;
    const dest: [*]u8 = @ptrCast(pv_data orelse return sa);
    @memcpy(dest[0..buffer.len], buffer);
    _ = sa_unaccess(sa);
    return sa;
}

fn createArgsSafeArray(
    args: []const []const u8,
    sa_create: FnSafeArrayCreate,
    sa_access: FnSafeArrayAccessData,
    sa_unaccess: FnSafeArrayUnaccessData,
    sys_alloc: FnSysAllocString,
) ?*SAFEARRAY {
    // Inner SAFEARRAY of BSTRs
    var bstr_bound = SAFEARRAYBOUND{ .c_elements = @intCast(args.len), .l_lbound = 0 };
    const bstr_sa = sa_create(VT_BSTR, 1, &bstr_bound) orelse return null;

    var bstr_data: ?*anyopaque = null;
    if (sa_access(bstr_sa, &bstr_data) < 0) return null;
    const bstr_arr: [*]*u16 = @ptrCast(@alignCast(bstr_data orelse return null));
    for (args, 0..) |arg, i| {
        // Convert ASCII to wide null-terminated
        var wide_buf: [512:0]u16 = undefined;
        for (arg, 0..) |byte, j| {
            wide_buf[j] = @as(u16, byte);
        }
        wide_buf[arg.len] = 0;
        const bstr = sys_alloc(@ptrCast(&wide_buf)) orelse return null;
        bstr_arr[i] = bstr;
    }
    _ = sa_unaccess(bstr_sa);

    // Outer SAFEARRAY of 1 VARIANT wrapping the BSTR array
    var outer_bound = SAFEARRAYBOUND{ .c_elements = 1, .l_lbound = 0 };
    const outer_sa = sa_create(VT_VARIANT, 1, &outer_bound) orelse return null;
    var outer_data: ?*anyopaque = null;
    if (sa_access(outer_sa, &outer_data) < 0) return null;
    const var_ptr: *VARIANT = @ptrCast(@alignCast(outer_data orelse return null));
    var_ptr.* = VARIANT{
        .vt = VT_ARRAY | VT_BSTR,
        .w_reserved1 = 0,
        .w_reserved2 = 0,
        .w_reserved3 = 0,
        .data = @intFromPtr(bstr_sa),
        ._pad = 0,
    };
    _ = sa_unaccess(outer_sa);
    return outer_sa;
}

// ============================================================================
// Main entry point
// ============================================================================

pub fn executeDotNetAssembly(buffer: []const u8, args: []const []const u8) !void {
    // --- Dynamic-load mscoree.dll and oleaut32.dll ---
    const mscoree = win.LoadLibraryA("mscoree.dll") orelse return error.MscoreeLoadFailed;
    const oleaut32 = win.LoadLibraryA("oleaut32.dll") orelse return error.Oleaut32LoadFailed;

    const clr_create_instance: FnCLRCreateInstance = @ptrCast(
        win.GetProcAddress(@ptrCast(mscoree), "CLRCreateInstance") orelse return error.CLRCreateInstanceNotFound,
    );

    const sa_create: FnSafeArrayCreate = @ptrCast(
        win.GetProcAddress(@ptrCast(oleaut32), "SafeArrayCreate") orelse return error.SafeArrayCreateNotFound,
    );
    const sa_access: FnSafeArrayAccessData = @ptrCast(
        win.GetProcAddress(@ptrCast(oleaut32), "SafeArrayAccessData") orelse return error.SafeArrayAccessDataNotFound,
    );
    const sa_unaccess: FnSafeArrayUnaccessData = @ptrCast(
        win.GetProcAddress(@ptrCast(oleaut32), "SafeArrayUnaccessData") orelse return error.SafeArrayUnaccessDataNotFound,
    );
    const sa_destroy: FnSafeArrayDestroy = @ptrCast(
        win.GetProcAddress(@ptrCast(oleaut32), "SafeArrayDestroy") orelse return error.SafeArrayDestroyNotFound,
    );
    const sys_alloc: FnSysAllocString = @ptrCast(
        win.GetProcAddress(@ptrCast(oleaut32), "SysAllocString") orelse return error.SysAllocStringNotFound,
    );

    // --- Extract .NET version from PE metadata ---
    const version = utils.getDotNetVersion(buffer) orelse return error.DotNetVersionNotFound;

    // Convert version to wide string
    var version_wide: [64:0]u16 = undefined;
    for (version, 0..) |byte, i| {
        version_wide[i] = @as(u16, byte);
    }
    version_wide[version.len] = 0;

    // --- COM chain: MetaHost -> RuntimeInfo -> RuntimeHost ---
    var meta_host: ?*anyopaque = null;
    var hr = clr_create_instance(&CLSID_CLR_META_HOST, &IID_ICLR_META_HOST, &meta_host);
    if (hr < 0 or meta_host == null) return error.CLRCreateInstanceFailed;

    // ICLRMetaHost::GetRuntime (slot 3)
    var runtime_info: ?*anyopaque = null;
    const get_runtime = vtblSlot(*const fn (
        *anyopaque,
        [*:0]const u16,
        *const GUID,
        *?*anyopaque,
    ) callconv(.c) HRESULT, meta_host.?, 3);
    hr = get_runtime(meta_host.?, @ptrCast(&version_wide), &IID_ICLR_RUNTIME_INFO, &runtime_info);
    if (hr < 0 or runtime_info == null) {
        releaseCom(meta_host);
        return error.GetRuntimeFailed;
    }

    // ICLRRuntimeInfo::GetInterface (slot 9)
    var runtime_host: ?*anyopaque = null;
    const get_interface = vtblSlot(*const fn (
        *anyopaque,
        *const GUID,
        *const GUID,
        *?*anyopaque,
    ) callconv(.c) HRESULT, runtime_info.?, 9);
    hr = get_interface(runtime_info.?, &CLSID_COR_RUNTIME_HOST, &IID_ICOR_RUNTIME_HOST, &runtime_host);
    if (hr < 0 or runtime_host == null) {
        releaseCom(runtime_info);
        releaseCom(meta_host);
        return error.GetInterfaceFailed;
    }

    // ICorRuntimeHost::Start (slot 10)
    const start_fn = vtblSlot(*const fn (*anyopaque) callconv(.c) HRESULT, runtime_host.?, 10);
    hr = start_fn(runtime_host.?);
    if (hr < 0) {
        releaseCom(runtime_host);
        releaseCom(runtime_info);
        releaseCom(meta_host);
        return error.RuntimeStartFailed;
    }

    // ICorRuntimeHost::GetDefaultDomain (slot 13)
    var app_domain_unk: ?*anyopaque = null;
    const get_default_domain = vtblSlot(*const fn (
        *anyopaque,
        *?*anyopaque,
    ) callconv(.c) HRESULT, runtime_host.?, 13);
    hr = get_default_domain(runtime_host.?, &app_domain_unk);
    if (hr < 0 or app_domain_unk == null) {
        releaseCom(runtime_host);
        releaseCom(runtime_info);
        releaseCom(meta_host);
        return error.GetDefaultDomainFailed;
    }

    // QueryInterface for _AppDomain (slot 0)
    var app_domain: ?*anyopaque = null;
    const qi = vtblSlot(*const fn (
        *anyopaque,
        *const GUID,
        *?*anyopaque,
    ) callconv(.c) HRESULT, app_domain_unk.?, 0);
    hr = qi(app_domain_unk.?, &IID_APP_DOMAIN, &app_domain);
    releaseCom(app_domain_unk);
    if (hr < 0 or app_domain == null) {
        releaseCom(runtime_host);
        releaseCom(runtime_info);
        releaseCom(meta_host);
        return error.QueryInterfaceAppDomainFailed;
    }

    // --- Load assembly from byte array ---
    const byte_sa = createSafeArrayFromBytes(buffer, sa_create, sa_access, sa_unaccess) orelse {
        releaseCom(app_domain);
        releaseCom(runtime_host);
        releaseCom(runtime_info);
        releaseCom(meta_host);
        return error.SafeArrayCreationFailed;
    };

    // _AppDomain::Load_3 (slot 45)
    var assembly: ?*anyopaque = null;
    const load_3 = vtblSlot(*const fn (
        *anyopaque,
        *SAFEARRAY,
        *?*anyopaque,
    ) callconv(.c) HRESULT, app_domain.?, 45);
    hr = load_3(app_domain.?, byte_sa, &assembly);
    _ = sa_destroy(byte_sa);
    if (hr < 0 or assembly == null) {
        releaseCom(app_domain);
        releaseCom(runtime_host);
        releaseCom(runtime_info);
        releaseCom(meta_host);
        return error.Load3Failed;
    }

    // _Assembly::get_EntryPoint (slot 16)
    var method_info: ?*anyopaque = null;
    const get_entry_point = vtblSlot(*const fn (
        *anyopaque,
        *?*anyopaque,
    ) callconv(.c) HRESULT, assembly.?, 16);
    hr = get_entry_point(assembly.?, &method_info);
    if (hr < 0 or method_info == null) {
        releaseCom(assembly);
        releaseCom(app_domain);
        releaseCom(runtime_host);
        releaseCom(runtime_info);
        releaseCom(meta_host);
        return error.GetEntryPointFailed;
    }

    // --- Invoke entry point ---
    const obj = empty_variant;
    var ret_val = empty_variant;

    const params_sa = createArgsSafeArray(args, sa_create, sa_access, sa_unaccess, sys_alloc);

    // _MethodInfo::Invoke_3 (slot 37)
    const invoke_3 = vtblSlot(*const fn (
        *anyopaque,
        VARIANT,
        ?*SAFEARRAY,
        *VARIANT,
    ) callconv(.c) HRESULT, method_info.?, 37);
    hr = invoke_3(method_info.?, obj, params_sa, &ret_val);

    // Cleanup
    if (params_sa) |sa| _ = sa_destroy(sa);
    releaseCom(method_info);
    releaseCom(assembly);
    releaseCom(app_domain);
    releaseCom(runtime_host);
    releaseCom(runtime_info);
    releaseCom(meta_host);

    if (hr < 0) return error.Invoke3Failed;
}
