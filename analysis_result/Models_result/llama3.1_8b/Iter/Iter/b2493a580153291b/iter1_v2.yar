rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 17 D0 00 00 }
        $pattern1 = { FF 15 98 52 F4 00 E8 4F 00 00 00 59 FF }
        $pattern2 = { 3D 00 10 00 10 0F 82 }

    condition:
        any of them
}