rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C1 FF FF FF 55 8B EC FF 75 08 }
        $pattern1 = { FF 15 CC 24 C0 00 }
        $pattern2 = { 0F 31 C0 8B EC FF 75 08 }

    condition:
        any of them
}