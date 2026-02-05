rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass detection using counterfactual analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { E8 ?? ?? ?? ?? 74 ?? 0C ?? ?? }
        $pattern2 = { E8 ?? ?? ?? ?? 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }

    condition:
        any of them
}