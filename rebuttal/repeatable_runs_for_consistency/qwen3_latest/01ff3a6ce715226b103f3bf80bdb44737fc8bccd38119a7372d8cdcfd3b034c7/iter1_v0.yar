rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF D2 50 51 52 56 56 6A 35 6A 00 51 51 8D B0 98 0C 00 00 }
        $pattern1 = { 75 3D 6D B8 F4 D7 98 55 55 8B EC 8B 45 08 8B 48 14 56 56 6A 35 }
        $pattern2 = { E8 74 0A 00 00 8B 55 14 8B 45 10 8B 4D 0C 83 C4 14 52 8B 16 50 }

    condition:
        any of them
}