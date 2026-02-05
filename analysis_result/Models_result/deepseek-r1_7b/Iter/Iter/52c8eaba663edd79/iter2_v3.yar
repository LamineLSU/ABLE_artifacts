rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved specific"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B }
        $pattern1 = { 85 C0 74 12 6A 5B E8 25 }
        $pattern2 = { EB 3F 8B CE ED 43 F8 25 }

    condition:
        any of them
}