rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 A9 16 01 00 }  // GetCurrentProcess@KERNEL32.DLL
        $pattern1 = { FF 15 1E 17 01 00 }  // TerminateProcess@KERNEL32.DLL
        $pattern2 = { FF 15 3F 18 01 00 }  // ExitProcess@KERNEL32.DLL

    condition:
        any of them
}