rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 ?? ?? ?? ?? }  // test + conditional jump
        $pattern1 = { E8 05 ?? ?? ?? ?? }  // call ExitProcess or similar API
        $pattern2 = { DC 8B 0D ?? ?? ?? ?? }  // timing check

    condition:
        any of them
}