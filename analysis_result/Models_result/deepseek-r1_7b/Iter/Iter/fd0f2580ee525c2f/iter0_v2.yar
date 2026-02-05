rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass detection for exit processes"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B CE FF F0 }
        $pattern1 = { BA 40 6A 5B ?? ?? ?? ?? 8B CE FF F1 }
        $pattern2 = { 03 C3 A1 88 ?? ?? ?? ?? 8B CE FF F2 }

    condition:
        any of them
}