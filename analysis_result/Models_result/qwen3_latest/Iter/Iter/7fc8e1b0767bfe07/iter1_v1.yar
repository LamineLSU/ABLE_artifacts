rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 E8 25 05 00 00 } // test, je, call to evasion function
        $pattern1 = { 85 C0 0F 84 33 FD FF FF }     // test, je with different offset
        $pattern2 = { FF 15 88 A0 00 00 }           // call to CloseHandle (cleanup check)

    condition:
        any of them
}