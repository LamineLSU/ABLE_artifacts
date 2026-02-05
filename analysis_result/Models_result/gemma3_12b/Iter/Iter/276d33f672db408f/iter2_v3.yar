rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC 8B 45 08 8B 48 10 56 6A 35 }
        $pattern1 = { 83 C4 14 52 8B 16 50 51 FF D2 }
        $pattern2 = { 3D 00 10 00 00 0F 82 }

    condition:
        any of them
}