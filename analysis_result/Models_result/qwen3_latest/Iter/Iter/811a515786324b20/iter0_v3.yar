rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 85 94 FD FF FF BA 03 00 00 00 E8 ?? ?? ?? ?? }
        $pattern1 = { 8B 85 94 FD FF FF E8 ?? ?? ?? ?? 8B 4D FC }
        $pattern2 = { 8B 45 F8 E8 ?? ?? ?? ?? 8B 45 F8 }

    condition:
        any of them
}