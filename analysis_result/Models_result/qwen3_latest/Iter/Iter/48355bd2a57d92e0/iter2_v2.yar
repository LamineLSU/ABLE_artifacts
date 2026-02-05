rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? 85 FF 74 ?? } // Call + test edi + je
        $pattern1 = { FF 15 44 A0 B8 00 50 FF 15 40 A0 B8 00 }   // GetProcessHeap -> HeapFree
        $pattern2 = { FF 15 7C A0 B8 00 83 3E 00 74 14 }       // CloseHandle + cmp + je

    condition:
        any of them
}