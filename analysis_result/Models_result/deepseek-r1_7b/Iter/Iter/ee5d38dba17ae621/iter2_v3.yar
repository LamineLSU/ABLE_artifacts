rule Bypass_Sample_Evasion
{
    meta:
        description = "Evasion bypass for VM analysis tool detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { 74 ?? 0F 85 C0 ?? ?? ?? ?? }
        $pattern2 = { E8 ?? ?? ?? ?? 0F 85 C0 }

    condition:
        any of them
}