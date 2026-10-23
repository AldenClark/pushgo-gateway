#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <libproc.h>
#include <mach/mach_time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

/* Only the explicitly supplied, same-effective-UID PID is queried. No scanning. */
static int fail(int pid, const char *stage, int code) {
    printf("{\"pid\":%d,\"userCPU_ns\":null,\"systemCPU_ns\":null,"
           "\"RSSbytes\":null,\"interrupt_wakes\":null,\"pkgIdle_wakes\":null,"
           "\"sourceAPI\":\"proc_pid_rusage/RUSAGE_INFO_V0\"}\n", pid);
    fprintf(stderr, "{\"status\":\"error\",\"stage\":\"%s\",\"error_code\":%d}\n", stage, code);
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 3 || strcmp(argv[1], "--owned-pid") != 0) {
        fprintf(stderr, "usage: %s --owned-pid PID\n", argv[0]);
        return 2;
    }
    char *end = NULL;
    errno = 0;
    long parsed = strtol(argv[2], &end, 10);
    if (errno || end == argv[2] || *end || parsed <= 0 || parsed > INT_MAX)
        return fail(0, "invalid_pid", EINVAL);
    int pid = (int)parsed;
    struct proc_bsdinfo before = {0}, after = {0};
    errno = 0;
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &before, sizeof(before)) != (int)sizeof(before))
        return fail(pid, "ownership_query", errno ? errno : EIO);
    if (before.pbi_uid != geteuid()) return fail(pid, "same_euid_required", EPERM);
    mach_timebase_info_data_t tb = {0};
    kern_return_t kr = mach_timebase_info(&tb);
    if (kr != KERN_SUCCESS || tb.denom == 0) return fail(pid, "mach_timebase_info", (int)kr);
    struct rusage_info_v0 ri = {0};
    errno = 0;
    if (proc_pid_rusage(pid, RUSAGE_INFO_V0, (rusage_info_t *)&ri) != 0)
        return fail(pid, "proc_pid_rusage", errno ? errno : EIO);
    if (ri.ri_proc_exit_abstime != 0) return fail(pid, "target_exited", ESRCH);
    errno = 0;
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &after, sizeof(after)) != (int)sizeof(after))
        return fail(pid, "identity_recheck", errno ? errno : EIO);
    if (after.pbi_uid != before.pbi_uid ||
        after.pbi_start_tvsec != before.pbi_start_tvsec ||
        after.pbi_start_tvusec != before.pbi_start_tvusec)
        return fail(pid, "pid_identity_changed", ESRCH);
    __uint128_t user_ns = (__uint128_t)ri.ri_user_time * tb.numer / tb.denom;
    __uint128_t system_ns = (__uint128_t)ri.ri_system_time * tb.numer / tb.denom;
    if (user_ns > UINT64_MAX || system_ns > UINT64_MAX) return fail(pid, "cpu_ns_overflow", ERANGE);
    printf("{\"pid\":%d,\"userCPU_ns\":%" PRIu64 ",\"systemCPU_ns\":%" PRIu64
           ",\"RSSbytes\":%" PRIu64 ",\"interrupt_wakes\":%" PRIu64
           ",\"pkgIdle_wakes\":%" PRIu64 ",\"sourceAPI\":\"proc_pid_rusage/RUSAGE_INFO_V0\"}\n",
           pid, (uint64_t)user_ns, (uint64_t)system_ns, ri.ri_resident_size,
           ri.ri_interrupt_wkups, ri.ri_pkg_idle_wkups);
    fprintf(stderr, "{\"status\":\"ok\",\"pid\":%d,\"user_time_raw_mach_ticks\":%" PRIu64
            ",\"system_time_raw_mach_ticks\":%" PRIu64 ",\"timebase_numer\":%u,\"timebase_denom\":%u,"
            "\"proc_start_abstime\":%" PRIu64 ",\"proc_exit_abstime\":%" PRIu64 "}\n",
            pid, ri.ri_user_time, ri.ri_system_time, tb.numer, tb.denom,
            ri.ri_proc_start_abstime, ri.ri_proc_exit_abstime);
    return 0;
}
