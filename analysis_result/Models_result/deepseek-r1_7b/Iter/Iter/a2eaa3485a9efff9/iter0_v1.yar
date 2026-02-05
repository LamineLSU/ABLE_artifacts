rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 BD 04 F9 FF FF 75 11 }
        $pattern1 = { E8 9D F4 FF FF 6A 00 }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 83 C4 }

    condition:
        any of them
}