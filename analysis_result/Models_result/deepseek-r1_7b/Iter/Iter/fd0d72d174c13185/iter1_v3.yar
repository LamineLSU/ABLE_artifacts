rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 25 05 00 ?? ?? ?? ?? ?? 0F 3C ?? }
        $pattern1 = { 74 1A 0F 84 ?? ?? ?? ?? FF 3E ?? ?? ?? ?? }
        $pattern2 = { 6A 5B 0F E8 05 00 ?? ?? ?? ?? 8B CE ?? }

    condition:
        any of them
}