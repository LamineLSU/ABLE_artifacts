rule MaliciousCodeDetection
{
    meta:
        description = "Detects malicious code patterns related to system time checks and exit process calls."
        cape_options = "bp0=$sys_time_check+0,action0=skip,bp1=$exit_process_call+0,action1=skip,bp2=$winmetafile_call+0,action2=skip,count=0"

    strings:
        // Pattern 1: Call to GetSystemTime, compare word at [esp], and conditional jump (jnc)
        $sys_time_check = { E8 B0 C8 F9 FF 66 81 3C 24 E4 07 73 07 }

        // Pattern 2: Push 0 followed by call to ExitProcess
        $exit_process_call = { 6A 00 E8 D1 C7 F9 FF }

        // Pattern 3: Call to GetWinMetaFileBits followed by push 0
        $winmetafile_call = { E8 6B 25 FE FF 6A 00 }

    condition:
        $sys_time_check or $exit_process_call or $winmetafile_call
}