rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 ?? 6A 5B } // test+je+push sequence
        $pattern1 = { FF 15 ?? ?? ?? ?? } // call to ExitProcess
        $pattern2 = { E8 ?? ?? ?? ?? 8B 45 FC } // conditional call+mov sequence

    condition:
        any of them
}