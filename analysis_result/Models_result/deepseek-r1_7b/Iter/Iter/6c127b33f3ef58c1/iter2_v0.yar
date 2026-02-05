rule Bypass_Evasion_Patterns
{
    meta:
        description = "Evasion bypass detection for specific patterns in x86"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 F9 4E 8B 45 FC }
        $pattern1 = { 74 3F FE 75 0E FF }
        $pattern2 = { 6A ?? 5A 8B CE E8 }

    condition:
        any of them
}