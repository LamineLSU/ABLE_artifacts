rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }
        $pattern1 = { 5A 53 6A 40 53 68 ?? ?? ?? ?? }
        $pattern2 = { 8B C7 5F 5E 33 CD 5B E8 ?? ?? ?? ?? }

    condition:
        any of them
}