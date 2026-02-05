rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 6A 5B 5A 8B CE E8 25 ?? ?? ?? ?? ?? 85 C0 }
        $pattern2 = { FF 75 08 FF 15 AC B0 41 ?? ?? ?? ?? ?? FF 75 08 FF 15 3C E1 CC }
    condition:
        any of them
}