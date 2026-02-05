rule Evasion_Bypass
{
    meta:
        description = "Detects evasion logic via test+jne, exit decision, and exit call"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Security Analyst"
        date = "2023-10-15"

    strings:
        $pattern0 = { 66 83 F8 01 75 0D }  // cmp ax, 0x01 + jne
        $pattern1 = { FF 15 38 51 A1 03 }  // call RtlExitUserThread
        $pattern2 = { FF 15 34 51 A1 03 }  // call ExitProcess

    condition:
        any of them
}