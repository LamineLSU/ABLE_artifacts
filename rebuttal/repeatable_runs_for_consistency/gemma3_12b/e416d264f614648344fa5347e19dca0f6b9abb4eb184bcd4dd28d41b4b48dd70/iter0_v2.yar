rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B D0 E8 DA FD FF FF 83 C4 20 }
        $pattern1 = { 85 C0 74 10 6A 00 FF 35 CC 1A 47 00 }
        $pattern2 = { 68 08 3D 46 00 8D 4C 24 2C E8 01 C1 FF FF }

    condition:
        any of them
}