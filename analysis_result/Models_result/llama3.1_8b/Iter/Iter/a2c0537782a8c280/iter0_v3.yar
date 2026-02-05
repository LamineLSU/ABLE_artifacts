rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,bp2=$pattern3+0,action2=skip,count=0"

    strings:
        $pattern1 = { 0F 84 ?? ?? ?? ?? 8B CE E8 ?? ?? ?? ?? }
        $pattern2 = { 6A 01 FF 15 A0 F6 00 8B EC E8 ?? ?? ?? ?? }
        $pattern3 = { 8B CE E8 ?? ?? ?? ?? 33 C9 EB A5 }

    condition:
        any of them
}