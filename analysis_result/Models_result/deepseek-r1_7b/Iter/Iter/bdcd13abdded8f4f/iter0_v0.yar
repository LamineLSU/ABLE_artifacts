rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass detection using YARA rules"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? E8 ?? ?? ?? }
        $pattern1 = { ?? ?? ?? ?? F8 03 07 ?? ?? ?? ?? F8 ?? }
        $pattern2 = { 6A ?? 5A 8B CE ?? ?? ?? ?? F8 03 }

    condition:
        any of them
}