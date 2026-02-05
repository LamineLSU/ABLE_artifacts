rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass detection for exit processes"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? 8B CE E8 ?? ?? 8B 45 F8 FC ?? ?? }
        $pattern1 = { 6A 5B 5A 8B CE E8 ?? ?? BA 04 01 00 00 ?? ?? }
        $pattern2 = { E8 25 05 00 00 ?? ?? 0F 84 FC ?? ?? }

    condition:
        any of them
}