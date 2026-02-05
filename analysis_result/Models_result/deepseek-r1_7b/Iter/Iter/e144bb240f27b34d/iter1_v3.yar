rule Bypass_Sample_Evasion
{
    meta:
        description = "Evasion bypass analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC E8 C8 FF FF } // Push ebp and call
        $pattern1 = { 55 8B EC ?? ?? E8 C8 FF FF } // Additional context around call
        $pattern2 = { 6A ?? 53 8B 45 ?? E8 C8 FF FF } // Displacement push before call

    condition:
        any of them
}