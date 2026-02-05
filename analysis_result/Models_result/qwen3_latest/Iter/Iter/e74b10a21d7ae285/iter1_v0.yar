rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 00 } // test eax, eax + je + push/pop sequence
        $pattern1 = { FF 15 88 A0 0B 00 } // call CloseHandle@KERNEL32
        $pattern2 = { FF 15 2C A1 0B 00 } // call ExitProcess@KERNEL32

    condition:
        any of them
}