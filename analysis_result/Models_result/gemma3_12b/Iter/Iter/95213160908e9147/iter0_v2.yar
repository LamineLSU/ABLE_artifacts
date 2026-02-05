rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC FF 75 08 E8 ?? ?? ?? ?? 59 }
        $pattern1 = { 74 07 50 FF 15 88 A0 1C 01 53 }
        $pattern2 = { 55 8B EC FF 75 08 E8 ?? ?? ?? ?? 59 FF 75 08 }

    condition:
        any of them
}