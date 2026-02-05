rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 68 D8 B0 41 00 6A 02 FF 15 28 44 41 00 }
        $pattern2 = { 83 7D 10 00 75 32 6A 00 FF 35 D4 B0 41 00 }

    condition:
        any of them
}