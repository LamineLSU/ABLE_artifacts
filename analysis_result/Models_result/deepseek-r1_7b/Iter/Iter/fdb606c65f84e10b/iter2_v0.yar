rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass detection for specific address contexts"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern1 = { FF 7E 26 00 00 01 8D 8D FE 00 00 01 8D 8D 00 00 33 CB FC 00 0C 5B }
        $pattern2 = { E8 FF ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? }

    condition:
        any of them
}