rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - more specific patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern1 = { 00 9D 61 A5 74 12 6A 5B 5A 5C F8 45 ?? ?? ?? ?? 0F 84 ?? }
        $pattern2 = { 00 9D 62 1A C3 ?? ?? ?? ?? 8B E5 }

    condition:
        any of them
}