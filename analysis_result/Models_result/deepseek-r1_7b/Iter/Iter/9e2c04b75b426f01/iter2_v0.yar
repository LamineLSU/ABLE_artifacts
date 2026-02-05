rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC }  // Targeting the early call/test/je pattern
        $pattern1 = { E9 B5 FC FF FF A1 88 85 B5 00 FF 15 2C A1 B5 00 }  // Conditional exit check before call
        $pattern2 = { 3D 00 10 00 00 00 00 01 ?? ?? 0F }  // Unique instruction sequence for timing bypass

    condition:
        any of them
}