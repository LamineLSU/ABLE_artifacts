rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass detection rules based on trace analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 6A 5B 5A 8B CE E8 25 05 00 00 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { 8B E5 FF 15 88 A0 F3 00 ?? ?? ?? ?? E8 0D 0C 00 00 }

    condition:
        any of them
}