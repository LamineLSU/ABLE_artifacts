rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 73 22 8B 55 E4 52 }  // JNC + mov + push (conditional check)
        $pattern1 = { FF 15 A4 50 61 00 }   // ExitProcess call (exit condition)
        $pattern2 = { FF 15 F0 50 61 00 }   // CloseHandle call (resource cleanup)

    condition:
        any of them
}