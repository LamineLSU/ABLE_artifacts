rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting memory-to-exception bypass"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 FC 8B CE EB 83 FF F0 E8 C1 63 DB }
        $pattern1 = { E8 ?? 83 C4 85 C0 0F 84 FC EB 83 FF F7 4B F6 }
        $pattern2 = { 6A ?? 5A 8B CE E8 C0 53 ?? 8B 4D F7 26 11 }

    condition:
        any of them
}