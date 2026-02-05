rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 FF 4B F3 FF ?? ?? ?? ?? 5A 8B CE E8 85 C0 }
        $pattern1 = { 6A 5B 5A 8B CE E8 74 07 FF 8D 8D F8 FE 85 C0 }
        $pattern2 = { 6A 5B 5A 8B CE E8 3C 3D 53 ?? ?? 85 C0 74 1E FF 53 53 ?? }

    condition:
        any of them
}