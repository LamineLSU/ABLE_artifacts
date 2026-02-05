rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF ?? ?? ?? 41 00 E8 C8 FF FF FF 8B C4 }
        $pattern1 = { E8 C8 FF FF FF E8 ?? ?? ?? ?? 83 F8 04 }
        $pattern2 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }

    condition:
        any of them
}