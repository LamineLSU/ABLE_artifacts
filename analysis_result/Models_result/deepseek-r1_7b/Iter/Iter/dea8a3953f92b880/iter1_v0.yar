rule Bypass_Sample_Evasion
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 ?? ?? ?? E8 ?? ?? ?? ?? }
        $pattern1 = { E8 C8 ?? ?? ?? ?? 8B EC FF FF FF ?? ?? }
        $pattern2 = { 6A EC 5A 8B CE E8 ?? ?? ?? ?? 0F C4 }

    condition:
        any of them
}