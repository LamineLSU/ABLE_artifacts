rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 80 7D F6 00 75 CC 83 65 F0 00 EB 08 }
        $pattern1 = { 8B 45 F0 89 45 E8 E8 C0 0E 01 00 }
        $pattern2 = { FF 15 2C 64 45 00 83 65 DC 00 EB 08 }

    condition:
        any of them
}