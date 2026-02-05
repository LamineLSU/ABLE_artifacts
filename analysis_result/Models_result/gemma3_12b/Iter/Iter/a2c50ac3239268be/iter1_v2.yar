rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 50 50 E8 ?? ?? ?? ?? 8B 03 }
        $pattern1 = { 8B F0 8B F0 B9 0C 00 00 00 F3 A5 }
        $pattern2 = { E9 67 FF FF FF FF 8B 03 }

    condition:
        any of them
}