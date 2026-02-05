rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved using multiple strategies"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 ?? ?? ?? ?? 6A 5B }
        $pattern1 = { 5A 8B CE E8 ?? ?? ?? ?? 85 C0 ?? ?? ?? }
        $pattern2 = { 68 40 53 ?? 6A 40 53 ?? DA 11 8B E5 }

    condition:
        any of them
}