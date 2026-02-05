rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 59 59 85 C0 0F 85 F2 CF FF FF }
        $pattern1 = { 6A 00 3B 75 04 74 1C 8B C7 }
        $pattern2 = { 80 7B 28 02 75 0E 83 3D 00 10 49 00 00 }

    condition:
        any of them
}