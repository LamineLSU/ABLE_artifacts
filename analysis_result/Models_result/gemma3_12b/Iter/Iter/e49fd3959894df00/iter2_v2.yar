rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 5C 75 44 00 50 FF 15 14 75 44 00 85 C0 75 07 }
        $pattern1 = { 8D 85 EC FE FF FF 5B 89 85 A8 FE FF FF 89 9D 94 FE FF FF }
        $pattern2 = { 6A 04 56 53 68 C0 9E E6 05 53 57 E8 82 3D 01 00 }

    condition:
        any of them
}