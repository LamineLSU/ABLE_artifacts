rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 FF 15 ?? ?? ?? ?? }
        $pattern1 = { E9 ?? ?? ?? ?? 6A 01 }
        $pattern2 = { 8B D0 E8 ?? ?? ?? ?? 83 C4 20 }

    condition:
        any of them
}