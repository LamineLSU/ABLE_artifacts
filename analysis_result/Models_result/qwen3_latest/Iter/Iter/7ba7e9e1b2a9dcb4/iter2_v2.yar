rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 ?? ?? ?? ?? }  // Test/je + push/pop + call
        $pattern1 = { 74 07 FF 15 ?? ?? ?? ?? }                     // Je + call to ExitProcess
        $pattern2 = { E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }     // Call + test/je pair

    condition:
        any of them
}