rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { E8 ?? ?? ?? ?? 83 C4 14 52 8B 16 50 51 FF FD }
        $pattern2 = { 6A 35 6A 00 51 8D B0 98 0C 00 00 56 50 E8 74 0A 00 00 8B 55 0C }

    condition:
        any of them
}