#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import sys
import shlex
import signal
import argparse
import subprocess
from hashlib import md5
from shutil import copyfile
from multiprocessing import Pool
from sysv_ipc import SharedMemory, IPC_PRIVATE, IPC_CREX

MAP_SIZE = 8 * 1024 * 1024

timeout_seconds = 1

stub_list = []

def cleanupSubprocesses(signum, frame):
    os.killpg(0, signal.SIGTERM)
    sys.exit()

# Prevent the program to break the original file
def copySeedFile(seed_path):
    tmpfile_path = "/tmp/.showmap-tmpfile-%s" % (md5(seed_path.encode("utf-8")).hexdigest())
    try:
        copyfile(seed_path, tmpfile_path)
    except IOError as e:
        print("Unable to copy the seed file %s: %s" % (seed_path, e))
        exit(1)
    except:
        print("Unexpected error:", sys.exc_info())
        exit(1)
    return tmpfile_path

def executeStub(stub):
    if not os.path.exists(stub.split(" ")[0]):
        print("ELF not found: %s" % (stub.split(" ")[0]))
        exit(1)
    find_seed_result = re.findall(r'output_\S+/id:\S+', stub)
    tmpfile_path = None
    seed_path = None
    if len(find_seed_result) > 0:
        seed_path = find_seed_result[0]
        tmpfile_path = copySeedFile(seed_path)
        stub = stub.replace(seed_path, tmpfile_path)

    execution_cmd = ("timeout %d %s" % (timeout_seconds, stub))
    # args = [e.strip() for e in re.sub(' +', ' ', execution_cmd).split(" ") if len(e) != 0 and not e.isspace()]
    args = shlex.split(execution_cmd)
    p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
    try:
        p.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
    except subprocess.SubprocessError as e:
        print(e.cmd)


    if tmpfile_path and os.path.exists(tmpfile_path):
        os.remove(tmpfile_path)

    return

def calibrateMapSize(stub):
    global MAP_SIZE
    err = None
    my_env = os.environ.copy()
    my_env["AFL_DEBUG"] = "1"
    args = shlex.split(stub)
    p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, preexec_fn=os.setsid, env=my_env)
    try:
        _, err = p.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
    except subprocess.SubprocessError as e:
        print(e.cmd)
    if err:
        find_map_result = re.search(re.compile("__afl_final_loc (\d+)"), err.decode("cp850"))
        if find_map_result:
            MAP_SIZE = int(find_map_result.group(1))
    return

def individualProcess(stub):
    shm = SharedMemory(IPC_PRIVATE, flags=IPC_CREX, mode=0o600, size=MAP_SIZE, init_character=b'\x00')

    os.environ['__AFL_SHM_ID'] = str(shm.id)
    os.environ['AFL_MAP_SIZE'] = str(MAP_SIZE)

    shm_content = shm.read()

    assert shm_content == bytes([0] * MAP_SIZE)

    executeStub(stub)

    shm_content = shm.read()

    shm.detach()
    shm.remove()

    if shm_content[0] == 0:
        print("[ERROR] No coverage detected!")
        exit(1)

    bitmap = []
    for i in range(1, MAP_SIZE):
        if shm_content[i] == 0:
            continue
        if not edges_only_flag:
            bitmap.append("%06d:%d" % (i, int(shm_content[i])))
        else:
            bitmap.append("%06d:%d" % (i, 1))

    with open("%s/%06d" % (output_path, stub_list.index(stub)), "w") as f:
        f.write("\n".join(bitmap))  
    
    # print("[+] Captured %d tuples." % (len(bitmap)))

    return

def parseArguments():
    parser = argparse.ArgumentParser(description="""
        PyShowmap - A Python wrapper for afl-showmap, providing support for multi-processing.
    """)
    parser.add_argument('-i', dest="stub_file", help='process all stubs in this file, must be combined with -o. With -C, -o is a file, without -C it must be a directory and each bitmap will be written there individually.', required=True)
    parser.add_argument("-o", dest="output_file", help="Path to write the trace data to.", required=True)
    parser.add_argument("-b", dest="cpu_ids", help="Bind the subprocesses to the specified CPU core, e.g., \"-b 0-3\" or \"-b 0,1,2,3\".(default=0)", required=False, default="0")
    parser.add_argument("-t", dest="timeout_seconds", help="Timeout seconds. (default=1)", required=False, default=1)
    parser.add_argument("-C", action='store_true', help="collect coverage, writes all edges to -o and gives a summary. Must be combined with -i.", required=False)
    parser.add_argument("-e", action='store_true', help="Show edge coverage only, ignore hit counts", required=False)

    args = parser.parse_args()

    stub_file_path = args.stub_file
    output_path = args.output_file
    cpu_ids = args.cpu_ids
    timeout_seconds = int(args.timeout_seconds)
    collect_coverage_flag = args.C
    edges_only_flag = args.e

    if not os.path.exists(stub_file_path) or os.path.isdir(stub_file_path):
        print("[-] Cannot find the input file: %s" % (stub_file_path))
        exit(1)
    if not collect_coverage_flag and os.path.exists(output_path) and not os.path.isdir(output_path):
        print("[-] without -C, -o must be a directory: %s" % output_path)
        exit(1)

    return stub_file_path, output_path, cpu_ids, timeout_seconds, collect_coverage_flag, edges_only_flag

def parseCoreArgument(str):
    core_list = []
    for s in str.split(","):
        if "-" in s:
            tmp_list = range(int(s.split("-")[0]), int(s.split("-")[1]) + 1)
            for ele in tmp_list:
                core_list.append(ele)
        else:
            core_list.append(int(s))
    return core_list

if __name__ == "__main__":

    stub_file_path, output_path, core_ids, timeout_seconds, collect_coverage_flag, edges_only_flag = parseArguments()
    
    core_list = parseCoreArgument(core_ids)
    os.sched_setaffinity(0, core_list)

    with open(stub_file_path, "r") as f:
        stub_list = [stub for stub in f.read().splitlines() if len(stub) > 0 and not stub.isspace()]

    # signal.signal(signal.SIGINT, cleanupSubprocesses)
    # signal.signal(signal.SIGTERM, cleanupSubprocesses)
    
    os.environ['LD_LIBRARY_PATH'] = "%s:%s" % (os.path.abspath(os.path.join(stub_list[0].split(" ")[0], "../../", "lib")), os.environ.get('LD_LIBRARY_PATH'))
    calibrateMapSize(stub_list[0].split(" ")[0])
    print("[*] Target Map Size: %d" % (MAP_SIZE))

    if collect_coverage_flag:
        shm = SharedMemory(IPC_PRIVATE, flags=IPC_CREX, mode=0o600, size=MAP_SIZE, init_character=b'\x00')

        os.environ['__AFL_SHM_ID'] = str(shm.id)
        os.environ['AFL_MAP_SIZE'] = str(MAP_SIZE)

        shm_content = shm.read()

        assert shm_content == bytes([0] * MAP_SIZE)

        with Pool(processes=len(os.sched_getaffinity(0))) as p:
            p.map(executeStub, stub_list)

        shm_content = shm.read()

        shm.detach()
        shm.remove()

        if shm_content[0] == 0:
            print("[ERROR] No coverage detected!")
            exit(1)

        bitmap = []
        for i in range(1, MAP_SIZE):
            if shm_content[i] == 0:
                continue
            if not edges_only_flag:
                bitmap.append("%06d:%d" % (i, int(shm_content[i])))
            else:
                bitmap.append("%06d:%d" % (i, 1))

        with open(output_path, "w") as f:
            f.write("\n".join(bitmap))  

        print("[+] Captured %d tuples." % (len(bitmap)))
    else:
        with Pool(processes=len(os.sched_getaffinity(0))) as p:
            p.map(individualProcess, stub_list)

    os.killpg(0, signal.SIGTERM)