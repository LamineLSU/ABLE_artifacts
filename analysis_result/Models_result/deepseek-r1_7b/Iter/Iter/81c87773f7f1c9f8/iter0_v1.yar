rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 20 ?? ?? ?? ?? E8 C8 FF FF }
        $pattern1 = { E8 74 FA FF FF ?? ?? 5B ?? ?? ?? ?? 6A 5B 8B CE E8 74 FA FF FF }
        $pattern2 = { 0F 84 85 C0 ?? ?? ?? ?? E8 C8 FF FF FF }

    condition:
        any of them
}