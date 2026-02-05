rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass using specific trace patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B 4F 8E 3F }
        $pattern1 = { 85 C0 74 12 6A 5B 5A 8B CE 0F 84 }
        $pattern2 = { 83 F8 01 74 12 8B 8B 4D 8E 3F }

    condition:
        (any of the patterns match the trace)
}