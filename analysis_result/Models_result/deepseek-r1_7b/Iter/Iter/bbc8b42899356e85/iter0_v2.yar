rule Bypass_Sample {
    meta:
        description = "Evasion bypass detected by skipping call instructions causing program exit"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,cable=`$patc0+$patc1+$patc2h'"

    strings:
        $pattern0 = { 6A 41 80 00 00 00 01 1D }  // Example pattern capturing the first call instruction
        $pattern1 = { 6A 4E 80 00 00 00 01 1F }  // Example pattern for a different bypass point
        $pattern2 = { 6A 50 80 00 00 00 01 23 }  // Another example pattern

    condition:
        any of the following conditions are true:
            - The program executed instruction matching $pattern0, leading to exit.
            - The program executed instruction matching $pattern1, leading to exit.
            - The program executed instruction matching $pattern2, leading to exit.

    exit_process: [hex_to_insn 6A41], [hex_to_insn 6A4E], [hex_to_insn 6A50]
}