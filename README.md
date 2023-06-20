# PyShowmap
A Python wrapper for afl-showmap, providing support for multi-processing.

## Usage

```
pyshowmap -i stub_file -o output [-b cpu_ids] [-t timeout] [-C] [-e]
```

## Stub File Demo
```
./build_afl++/bin/tiffcp output_tiffcp_afl++_1/default/hangs/id:000021,src:005694,time:157071170,execs:66037688,op:havoc,rep:4 /tmp/foo
./build_afl++/bin/tiffcp output_tiffcp_afl++_1/default/hangs/id:000007,src:001722,time:4918184,execs:1614733,op:havoc,rep:2 /tmp/foo
./build_afl++/bin/tiffcp output_tiffcp_afl++_1/default/hangs/id:000012,src:004340,time:44104468,execs:15504397,op:havoc,rep:2 /tmp/foo
./build_afl++/bin/tiffcp output_tiffcp_afl++_1/default/hangs/id:000016,src:004180,time:67350244,execs:23849303,op:havoc,rep:2 /tmp/foo
./build_afl++/bin/tiffcp output_tiffcp_afl++_1/default/hangs/id:000002,src:001015,time:1260983,execs:425125,op:havoc,rep:16 /tmp/foo
./build_afl++/bin/tiffcp output_tiffcp_afl++_1/default/hangs/id:000014,src:004195,time:50315028,execs:17697964,op:havoc,rep:2 /tmp/foo
./build_afl++/bin/tiffcp output_tiffcp_afl++_1/default/hangs/id:000005,src:001261,time:1819795,execs:594456,op:havoc,rep:2 /tmp/foo
./build_afl++/bin/tiffcp output_tiffcp_afl++_1/default/hangs/id:000004,src:001261,time:1808319,execs:591256,op:havoc,rep:8 /tmp/foo
./build_afl++/bin/tiffcp output_tiffcp_afl++_1/default/hangs/id:000019,src:005343,time:116552349,execs:45015630,op:havoc,rep:4 /tmp/foo
```