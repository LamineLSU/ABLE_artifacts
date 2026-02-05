rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved using specific check points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 5A 8B 45 F7 D6 6C 33 20 C0 C8 3E 90 04 0C 5A 15 0C 8B D0 3C }
        $pattern1 = { FD 07 E5 B0 C8 67 D6 D1 C8 12 55 B6 D1 C9 0C 40 C9 F1 1B 40 C8 12 55 }
        $pattern2 = { 8D 3F 71 D0 01 01 00 01 01 01 }

    condition:
        (any of them)
}