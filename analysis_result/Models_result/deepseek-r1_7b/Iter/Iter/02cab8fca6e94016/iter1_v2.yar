rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { FF 15 AC B0 41 00 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { 74 ?? ?? ?? ?? 0F 85 }

    condition:
        any of them
}