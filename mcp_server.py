import asyncio
import psutil
import re
import os
from collections import deque

from mcp.server.mcpserver import MCPServer


# ============================================================
# MCP SERVER
# ============================================================

server = MCPServer(
    name="Local OS Diagnostic Server",
    version="1.0.0"
)


# ============================================================
# SYSTEM METRICS
# ============================================================

@server.tool()
async def get_system_metrics() -> dict:
    """Get current CPU, RAM, and disk usage."""

    cpu = psutil.cpu_percent(interval=1)

    memory = psutil.virtual_memory()

    disk = psutil.disk_usage("C:\\")

    return {
        "cpu_percent": cpu,
        "memory_percent": memory.percent,
        "disk_percent": disk.percent
    }


# ============================================================
# FIND PROCESS BY PORT
# ============================================================

@server.tool()
async def find_process_by_port(port: int) -> dict:
    """Find the process using a specific network port."""

    matches = []

    for conn in psutil.net_connections(kind="inet"):

        if conn.laddr and conn.laddr.port == port:

            pid = conn.pid

            if pid is not None:

                try:

                    process = psutil.Process(pid)

                    matches.append({
                        "pid": pid,
                        "name": process.name(),
                        "status": process.status(),
                        "address": f"{conn.laddr.ip}:{conn.laddr.port}"
                    })

                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied
                ):
                    pass

    return {
        "port": port,
        "processes": matches
    }


# ============================================================
# INSPECT PROCESS
# ============================================================

@server.tool()
async def inspect_process(pid: int) -> dict:
    """Get detailed information about a running process."""

    try:

        process = psutil.Process(pid)

        memory = process.memory_info()

        return {
            "pid": pid,
            "name": process.name(),
            "status": process.status(),
            "cpu_percent": process.cpu_percent(interval=0.5),
            "memory_percent": process.memory_percent(),
            "memory_mb": round(
                memory.rss / (1024 * 1024),
                2
            ),
            "num_threads": process.num_threads(),
            "exe": process.exe()
        }

    except psutil.NoSuchProcess:

        return {
            "error": f"Process {pid} does not exist."
        }

    except psutil.AccessDenied:

        return {
            "error": (
                f"Access denied while inspecting process {pid}."
            )
        }


# ============================================================
# FIND HIGH-CONSUMPTION PROCESSES
# ============================================================

@server.tool()
async def find_high_consumption_processes(
    top_n: int = 5,
    sort_by: str = "cpu"
) -> dict:
    """
    Find processes currently consuming the most CPU.
    Also returns each process's memory usage for additional context.
    """

    if sort_by not in ["cpu", "memory"]:

        return {
            "error": (
                "sort_by must be either 'cpu' or 'memory'."
            )
        }

    processes = []

    for process in psutil.process_iter(
        [
            "pid",
            "name",
            "memory_percent"
        ]
    ):

        try:

            # Ignore Windows System Idle Process
            if process.info["pid"] == 0:
                continue

            cpu_percent = process.cpu_percent(
                interval=0.2
            )

            memory_percent = process.info[
                "memory_percent"
            ]

            processes.append({
                "pid": process.info["pid"],
                "name": process.info["name"],
                "cpu_percent": round(
                    cpu_percent,
                    2
                ),
                "memory_percent": round(
                    memory_percent,
                    2
                )
            })

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            pass

    if sort_by == "cpu":

        processes.sort(
            key=lambda p: p["cpu_percent"],
            reverse=True
        )

    else:

        processes.sort(
            key=lambda p: p["memory_percent"],
            reverse=True
        )

    return {
        "sort_by": sort_by,
        "processes": processes[:top_n]
    }


# ============================================================
# LOG SECURITY
# ============================================================

def sanitize_logs(text: str) -> str:
    """
    Redact common secrets before logs are sent to the LLM.
    """

    # Password
    text = re.sub(
        r'(?i)(password\s*[:=]\s*)[^\s,;]+',
        r'\1[REDACTED]',
        text
    )

    # API key
    text = re.sub(
        r'(?i)(api[_-]?key\s*[:=]\s*)[^\s,;]+',
        r'\1[REDACTED]',
        text
    )

    # Bearer token
    text = re.sub(
        r'(?i)(authorization\s*:\s*bearer\s+)[^\s]+',
        r'\1[REDACTED]',
        text
    )

    return text


# ============================================================
# PROMPT-INJECTION / SUSPICIOUS LOG DETECTION
# ============================================================

def detect_suspicious_log_lines(
    text: str
) -> list[str]:
    """
    Detect log lines that contain instruction-like content.
    """

    suspicious_patterns = [

        r"ignore (all )?previous instructions",

        r"ignore the previous instructions",

        r"run (this|the following) command",

        r"execute (this|the following) command",

        r"delete (this|the) .*file",

        r"remove (this|the) .*file",

        r"follow these instructions",

    ]

    suspicious_lines = []

    for line in text.splitlines():

        for pattern in suspicious_patterns:

            if re.search(
                pattern,
                line,
                re.IGNORECASE
            ):

                suspicious_lines.append(line)

                break

    return suspicious_lines


# ============================================================
# LOG RELEVANCE FILTER
# ============================================================

def filter_relevant_log_lines(
    text: str,
    max_lines: int = 50
) -> list[str]:
    """
    Extract log lines that are likely to contain useful
    diagnostic information.

    Priority is given to:
    ERROR
    WARN
    EXCEPTION
    FAILED
    FAILURE
    CRITICAL
    FATAL
    TIMEOUT
    REFUSED
    DENIED
    CRASH
    SHUTDOWN
    STARTUP
    """

    diagnostic_patterns = [

        r"\bERROR\b",
        r"\bWARN(?:ING)?\b",
        r"\bEXCEPTION\b",
        r"\bFAILED\b",
        r"\bFAILURE\b",
        r"\bCRITICAL\b",
        r"\bFATAL\b",
        r"\bTIMEOUT\b",
        r"\bREFUSED\b",
        r"\bDENIED\b",
        r"\bCRASH(?:ED)?\b",
        r"\bSTARTUP\b",
        r"\bSHUTDOWN\b",

        # Common application/database/network errors
        r"address already in use",
        r"connection refused",
        r"connection failed",
        r"database connection",
        r"out of memory",
        r"out-of-memory",
        r"permission denied",
        r"not found",
        r"unable to",
        r"cannot",
        r"could not",
    ]

    relevant_lines = []

    for line in text.splitlines():

        if any(
            re.search(
                pattern,
                line,
                re.IGNORECASE
            )
            for pattern in diagnostic_patterns
        ):

            relevant_lines.append(line)

    # Keep only the most recent relevant lines
    return relevant_lines[-max_lines:]


# ============================================================
# READ RECENT LOGS
# ============================================================

@server.tool()
async def read_recent_logs(
    path: str,
    lines: int = 50
) -> dict:
    """
    Read recent log lines and return security-sanitized,
    diagnostically relevant content.
    """

    try:

        # --------------------------------------------------------
        # Validate requested number of lines
        # --------------------------------------------------------

        if lines < 1:

            return {
                "error": (
                    "lines must be greater than 0."
                )
            }

        # Prevent huge log reads
        lines = min(
            lines,
            200
        )

        # --------------------------------------------------------
        # Read recent lines
        # --------------------------------------------------------

        with open(
            path,
            "r",
            encoding="utf-8",
            errors="replace"
        ) as file:

            recent_lines = deque(
                file,
                maxlen=lines
            )

        raw_content = "".join(
            recent_lines
        )

        # --------------------------------------------------------
        # Security sanitization
        # --------------------------------------------------------

        sanitized_content = sanitize_logs(
            raw_content
        )

        # --------------------------------------------------------
        # Detect suspicious instructions
        # --------------------------------------------------------

        suspicious_lines = detect_suspicious_log_lines(
            sanitized_content
        )

        # --------------------------------------------------------
        # Extract diagnostically relevant lines
        # --------------------------------------------------------

        relevant_lines = filter_relevant_log_lines(
            sanitized_content
        )

        # --------------------------------------------------------
        # Decide what to send to the LLM
        # --------------------------------------------------------

        if relevant_lines:

            filtered_content = "\n".join(
                relevant_lines
            )

        else:

            # If no diagnostic lines were detected,
            # return the recent content instead of returning
            # an empty result.
            filtered_content = sanitized_content

        # --------------------------------------------------------
        # Return structured result
        # --------------------------------------------------------

        return {

            "path": path,

            "lines_requested": lines,

            "lines_returned": len(
                recent_lines
            ),

            "relevant_lines_found": len(
                relevant_lines
            ),

            "content": filtered_content,

            "suspicious_instruction_lines":
                suspicious_lines
        }

    except FileNotFoundError:

        return {
            "error": (
                f"Log file not found: {path}"
            )
        }

    except PermissionError:

        return {
            "error": (
                f"Permission denied while reading: {path}"
            )
        }

    except Exception as e:

        return {
            "error": (
                f"Failed to read log file: {str(e)}"
            )
        }

@server.tool()
async def discover_logs() -> dict:
    """Discover approved application log files available for diagnostics."""

    current_dir = os.getcwd()

    approved_logs = []

    for filename in [
        "test_app.log",
        "malicious_test.log"
    ]:
        path = os.path.join(current_dir, filename)

        if os.path.isfile(path):
            approved_logs.append({
                "name": filename,
                "path": path
            })

    return {
        "directory": current_dir,
        "logs": approved_logs
    }

# ============================================================
# SERVER ENTRY POINT
# ============================================================

async def main():

    await server.run_stdio_async()


if __name__ == "__main__":

    asyncio.run(main())