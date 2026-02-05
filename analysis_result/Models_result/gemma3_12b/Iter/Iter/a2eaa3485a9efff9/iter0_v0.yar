rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 13 51 40 00 E8 1D 03 00 00 }
        $pattern1 = { 83 BD 04 F9 FF FF 01 6A 00 }
        $pattern2 = { E8 6B 07 00 00 8D 45 C4 50 }

    condition:
        any of them
}