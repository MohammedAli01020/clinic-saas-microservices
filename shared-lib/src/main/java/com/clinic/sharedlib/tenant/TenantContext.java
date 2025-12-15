package com.clinic.sharedlib.tenant;

/**
 * ThreadLocal holder for current request tenant id.
 * Set this at the beginning of request (Gateway or local interceptor) and clear
 * at the end.
 *
 * IMPORTANT:
 * - This is intentionally a bare utility (no Spring annotations).
 * - Services must ensure clear() is called (e.g. in interceptor/Filter
 * afterCompletion).
 */
public final class TenantContext {
    private static final ThreadLocal<String> CURRENT = new ThreadLocal<>();

    private TenantContext() {}

    public static void setTenantId(String tenantId) { CURRENT.set(tenantId); }

    public static String getTenantId() { return CURRENT.get(); }

    public static void clear() { CURRENT.remove(); }
}