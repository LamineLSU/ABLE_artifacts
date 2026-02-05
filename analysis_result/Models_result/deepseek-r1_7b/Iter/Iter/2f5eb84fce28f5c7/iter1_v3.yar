rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B CE ?? ?? ?? ?? ?? ?? } // After call and test
        $pattern1 = { E8 25 05 00 00 ?? ?? ?? ?? ?? ?? ?? ?? } // Specific offset after call in trace //1
        $pattern2 = { E9 B5 FC FF FF ?? ?? ?? ?? ?? ?? ?? ?? } // Similar pattern with different offset from trace //2

    condition:
        any of them
}