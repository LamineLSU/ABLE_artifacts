rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B }  // test+je+push sequence
        $pattern1 = { FF 15 ?? ?? ?? ?? }  // conditional call to address
        $pattern2 = { A1 88 85 3D 00 85 C0 }  // mov+test sequence

    condition:
        any of them
}