rule Bypass_Sample
{
    meta:
        description = "Evasion bypass analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C8 FF FF 5A 8B 4D 08 50 }
        $pattern1 = { FF 75 08 55 C0 ?? ?? F9 C0 }
        $pattern2 = { E8 C8 FF FF 5A 8B 4D 08 ?? }

    condition:
        any of them
}