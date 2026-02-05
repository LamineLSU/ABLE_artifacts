rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - target specific conditional checks in first 30% of trace"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 FE 84 }
        $pattern1 = { 00 A4 61 7A 85 C0 5A 74 12 }
        $pattern2 = { 8B C7 EB 03 8D 43 01 }

    condition:
        any of them
}