rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific test and jump sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 33 FD 00 00 00 00 00 00 }
        $pattern1 = { 74 12 6A 5B 00 00 00 00 00 00 00 00 }
        $pattern2 = { 8B CE 0F 84 33 FD 00 00 00 00 00 00 }

    condition:
        any of them
}