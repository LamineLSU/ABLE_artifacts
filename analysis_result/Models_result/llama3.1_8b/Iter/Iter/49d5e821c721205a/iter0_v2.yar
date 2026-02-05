rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 2C A1 3D 00 ?? ?? ?? ?? FF 15 2C A1 3D 00 }
        $pattern1 = { FF 15 2C A1 30 00 ?? ?? ?? ?? FF 15 2C A1 30 00 }
        $pattern2 = { FF 15 8C E1 22 01 ?? ?? ?? ?? FF 15 8C E1 22 01 }

    condition:
        any of them
}