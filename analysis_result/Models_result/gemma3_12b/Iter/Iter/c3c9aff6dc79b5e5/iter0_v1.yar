rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 83 7D 10 00 75 32 6A 09 FF 35 D4 B0 41 00 FF 15 90 44 41 00 }
        $pattern2 = { FF 15 38 41 41 00 FF 15 8C 44 41 00 68 C0 5E 41 00 6A 00 }

    condition:
        any of them
}