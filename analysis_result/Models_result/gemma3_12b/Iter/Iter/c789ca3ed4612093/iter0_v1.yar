rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 ?? ?? ?? ?? 83 F8 ?? }
        $pattern1 = { 64 A1 ?? ?? ?? ?? 8B 40 ?? C1 E8 ?? A8 01 }
        $pattern2 = { FF 75 ?? FF 15 ?? ?? ?? ?? }

    condition:
        any of them
}