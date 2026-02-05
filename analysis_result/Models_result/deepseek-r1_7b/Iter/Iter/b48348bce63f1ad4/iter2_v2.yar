rule Bypass_Sample
{
    meta:
        description = "Evasion bypass analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC FF 75 00 00 00 E8 C1 FF FF }
        $pattern1 = { 6A 00 8B EC FF 75 00 00 00 83 C4 FF }
        $pattern2 = { 8B 4D 05 00 00 00 59 00 83 C2 08 }

    condition:
        any of them
}