rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 8B CE E8 25 05 00 00 } // Test/je evasion check
        $pattern1 = { FF 15 88 A0 E0 00 } // CloseHandle API call (exit preparation)
        $pattern2 = { 53 BA 21 05 00 00 53 6A 40 } // Debug setup before ExitProcess

    condition:
        any of them
}