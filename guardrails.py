import os


# ============================================================
# POLICY
# ============================================================

# Only these files in the copilot working directory may be read.
APPROVED_LOG_FILENAMES = (
    "test_app.log",
    "malicious_test.log",
)

MIN_PORT = 1
MAX_PORT = 65535

MIN_TOP_N = 1
MAX_TOP_N = 20

MAX_LOG_LINES = 200


# ============================================================
# LOG PATH ALLOWLIST
# ============================================================

def approved_log_directory(base_dir: str | None = None) -> str:
    """Return the directory that owns the approved log files."""

    return os.path.abspath(base_dir or os.getcwd())


def approved_log_paths(base_dir: str | None = None) -> list[str]:
    """Return absolute paths of approved log files that currently exist."""

    directory = approved_log_directory(base_dir)
    paths = []

    for filename in APPROVED_LOG_FILENAMES:
        path = os.path.abspath(os.path.join(directory, filename))

        if os.path.isfile(path):
            paths.append(path)

    return paths


def normalize_log_path(path: str, base_dir: str | None = None) -> str:
    """Resolve a requested log path against the approved log directory."""

    directory = approved_log_directory(base_dir)

    if os.path.isabs(path):
        return os.path.abspath(path)

    return os.path.abspath(os.path.join(directory, path))


def is_approved_log_path(
    path: str,
    base_dir: str | None = None
) -> bool:
    """
    Return True only when the requested path resolves to an
    allowlisted log file in the approved directory.
    """

    if not isinstance(path, str) or not path.strip():
        return False

    requested = os.path.normcase(
        normalize_log_path(path, base_dir)
    )
    directory = os.path.normcase(
        approved_log_directory(base_dir)
    )

    allowed = {
        os.path.normcase(
            os.path.abspath(os.path.join(directory, filename))
        )
        for filename in APPROVED_LOG_FILENAMES
    }

    if requested not in allowed:
        return False

    # Extra traversal check: the resolved file must stay in-directory.
    try:
        common = os.path.commonpath([requested, directory])
    except ValueError:
        return False

    return common == directory


# ============================================================
# ARGUMENT CHECKS
# ============================================================

def check_log_path(path) -> tuple[bool, str]:
    """Validate a read_recent_logs path against the allowlist."""

    if not isinstance(path, str) or not path.strip():
        return (
            False,
            "The 'path' argument must be a non-empty string."
        )

    if not is_approved_log_path(path):
        return (
            False,
            (
                "Log path is not on the approved allowlist. "
                "Use discover_logs and only read a returned path."
            )
        )

    return True, ""


def check_port(port) -> tuple[bool, str]:
    """Validate a TCP/UDP port number."""

    if not isinstance(port, int) or isinstance(port, bool):
        return (
            False,
            "The 'port' argument must be an integer."
        )

    if port < MIN_PORT or port > MAX_PORT:
        return (
            False,
            (
                f"Port {port} is outside the allowed range "
                f"{MIN_PORT}-{MAX_PORT}."
            )
        )

    return True, ""


def check_pid_value(pid) -> tuple[bool, str]:
    """Validate PID type and basic range, not evidence membership."""

    if not isinstance(pid, int) or isinstance(pid, bool):
        return (
            False,
            "The 'pid' argument must be an integer."
        )

    if pid <= 0:
        return (
            False,
            "The 'pid' argument must be a positive integer."
        )

    return True, ""


def check_top_n(top_n) -> tuple[bool, str]:
    """Limit how many processes a ranking tool may return."""

    if not isinstance(top_n, int) or isinstance(top_n, bool):
        return (
            False,
            "The 'top_n' argument must be an integer."
        )

    if top_n < MIN_TOP_N or top_n > MAX_TOP_N:
        return (
            False,
            (
                f"top_n must be between {MIN_TOP_N} and "
                f"{MAX_TOP_N}."
            )
        )

    return True, ""


def check_sort_by(sort_by) -> tuple[bool, str]:
    """Restrict process ranking to supported fields."""

    if sort_by not in ("cpu", "memory"):
        return (
            False,
            "sort_by must be either 'cpu' or 'memory'."
        )

    return True, ""


def check_log_lines(lines) -> tuple[bool, str]:
    """Validate requested log line count before clamping."""

    if not isinstance(lines, int) or isinstance(lines, bool):
        return (
            False,
            "The 'lines' argument must be an integer."
        )

    if lines < 1:
        return (
            False,
            "lines must be greater than 0."
        )

    return True, ""


def clamp_log_lines(lines: int) -> int:
    """Cap log reads so a single call cannot dump a huge file."""

    return min(lines, MAX_LOG_LINES)
