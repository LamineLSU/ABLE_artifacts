rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { 64 A1 ?? ?? ?? ?? 8B 40 68 C1 E8 08 }
        $pattern2 = { FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? }

    condition:
        any of them
}