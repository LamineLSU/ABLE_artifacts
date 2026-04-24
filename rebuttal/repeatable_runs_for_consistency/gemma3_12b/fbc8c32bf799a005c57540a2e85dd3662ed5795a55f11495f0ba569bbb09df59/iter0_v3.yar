rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 81 6A 05 6A 00 50 68 50 80 85 00 51 6A 00 FF 15 C8 81 85 00 }
        $pattern1 = { 3D 97 00 00 00 75 DD 89 E0 8D 4C 24 18 6A 05 6A 00 50 68 50 80 85 00 }
        $pattern2 = { 85 C0 74 06 E8 EF 0F 00 00 }

    condition:
        any of them
}