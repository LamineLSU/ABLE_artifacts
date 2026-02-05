rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 8B CE }  // Test + je + mov (early evasion check)
        $pattern1 = { E8 25 05 00 00 85 C0 0F 84 ?? ?? ?? ?? }  // Call + test + je (conditional flow)
        $pattern2 = { FF 15 ?? ?? ?? ?? }  // ExitProcess API call (exit decision point)

    condition:
        any of them
}