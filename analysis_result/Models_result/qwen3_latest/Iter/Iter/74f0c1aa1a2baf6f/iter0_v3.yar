rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 56 FF 15 ?? ?? ?? ?? }
        $pattern1 = { 8B F0 E8 1D 00 00 00 }
        $pattern2 = { 84 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }

    condition:
        any of them
}