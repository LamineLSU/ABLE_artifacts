rule Bypass_Sample_Evasion
{
    meta:
        description = "Evasion bypass rule - sample"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 ?? ?? ?? ?? ?? 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { 75 0D 7E 2A ?? ?? FF 15 7C ?? ?? }
        $pattern2 = { E8 ?? ?? ?? ?? 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }

    condition:
        any of them
}