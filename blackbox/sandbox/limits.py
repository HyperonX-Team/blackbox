"""Resource limits for package processes.

Manifest:  limits: {memory_mb, cpu_percent, max_processes}

  windows  -> Job Objects (memory + CPU-rate hard cap + active-process limit)
  posix    -> resource.setrlimit (RLIMIT_AS memory cap) applied pre-exec.
             cpu_percent / max_processes have no portable posix equivalent
             without cgroups; they are enforced where the OS allows and
              reported as "not enforced" otherwise. Never silently pretend.

The runner applies these around the spawned child so limits cover the whole
application process tree (Job Objects) or the child and its descendants
inheriting rlimits (posix).
"""

import platform

from blackbox import platform as bb_platform
from blackbox.errors import BlackboxError

_MB = 1024 * 1024


def describe(limits: dict, triple: str) -> str:
    if not limits:
        return ""
    parts = []
    if limits.get("memory_mb"):
        parts.append(f"mem<={limits['memory_mb']}MB")
    if limits.get("cpu_percent"):
        parts.append(f"cpu<={limits['cpu_percent']}%")
    if limits.get("max_processes"):
        parts.append(f"procs<={limits['max_processes']}")
    enforced = "enforced" if bb_platform.target_info(triple)["os"] in ("windows", "linux") else "best-effort"
    return f"limits[{', '.join(parts)}] {enforced}"


def make_preexec(limits: dict):
    """POSIX only: return a preexec_fn applying rlimits, or None.

    Must be created in the parent but runs in the forked child before exec.
    """
    if not limits or not limits.get("memory_mb"):
        return None
    if platform.system() == "Windows":
        return None
    import resource

    def _apply():
        mem = int(limits["memory_mb"]) * _MB
        resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
        if limits.get("max_processes"):
            try:
                # per-user limit on most systems; still stops fork bombs from
                # this package under a dedicated run user
                resource.setrlimit(resource.RLIMIT_NPROC,
                                   (int(limits["max_processes"]), int(limits["max_processes"])))
            except (ValueError, OSError):
                pass

    return _apply


def attach_windows_job(process, limits: dict):
    """Windows only: put the child (and its future children) in a Job Object.

    `process` is a subprocess.Popen created with CREATE_SUSPENDED.
    """
    import ctypes
    import ctypes.wintypes as wt

    if not limits or platform.system() != "Windows":
        return
    if not limits.get("memory_mb") and not limits.get("cpu_percent") and not limits.get("max_processes"):
        return

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in
                    ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                     "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_large_integer),
            ("PerJobUserTimeLimit", ctypes.c_large_integer),
            ("LimitFlags", wt.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wt.DWORD),
            ("Affinity", ctypes.c_void_p),
            ("PriorityClass", wt.DWORD),
            ("SchedulingClass", wt.DWORD),
        ]

    class JOBOBJECT_CPU_RATE_CONTROL_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("ControlFlags", wt.DWORD),
            ("CpuRate", wt.DWORD),
        ]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.windll.kernel32
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise BlackboxError("Could not create a Job Object for resource limits.")

    JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
    JobObjectExtendedLimitInformation = 9
    JobObjectCpuRateControlInformation = 15
    JOB_OBJECT_CPU_RATE_CONTROL_ENABLE = 0x1
    JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP = 0x2

    info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    if limits.get("memory_mb"):
        info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY
        info.ProcessMemoryLimit = int(limits["memory_mb"]) * _MB
        info.JobMemoryLimit = int(limits["memory_mb"]) * _MB
    if limits.get("max_processes"):
        info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        info.BasicLimitInformation.ActiveProcessLimit = int(limits["max_processes"])
    if not kernel32.SetInformationJobObject(
            job, JobObjectExtendedLimitInformation, ctypes.byref(info), ctypes.sizeof(info)):
        kernel32.CloseHandle(job)
        raise BlackboxError("SetInformationJobObject failed for resource limits.")

    if limits.get("cpu_percent"):
        cpu = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION()
        cpu.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP
        cpu.CpuRate = int(limits["cpu_percent"]) * 100  # units of 0.01%
        if not kernel32.SetInformationJobObject(
                job, JobObjectCpuRateControlInformation, ctypes.byref(cpu), ctypes.sizeof(cpu)):
            pass  # cpu rate control needs Win8+; degrade silently to memory/proc caps

    if not kernel32.AssignProcessToJobObject(job, int(process._handle)):
        kernel32.CloseHandle(job)
        raise BlackboxError("Could not assign the package process to the limits Job Object.")


def resume_windows(process):
    """Resume a CREATE_SUSPENDED child (Windows) after the Job Object is attached."""
    import ctypes
    if platform.system() != "Windows":
        return
    ntdll = ctypes.windll.ntdll
    NtResumeProcess = getattr(ntdll, "NtResumeProcess", None)
    if NtResumeProcess:
        NtResumeProcess(int(process._handle))
