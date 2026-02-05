rule Bypass_Sample_Evasion
{
    meta:
        description = "Evasion bypass detection targeting specific call sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { 74 0F 84 ?? ?? ?? ?? }
        $pattern2 = { 0F 85 8C ?? ?? ?? ?? }

    condition:
        any of the patterns match specific call sequences aimed at bypassing security
}