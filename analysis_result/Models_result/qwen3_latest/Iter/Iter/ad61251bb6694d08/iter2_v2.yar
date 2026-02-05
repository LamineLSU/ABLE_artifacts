rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B }  // test+je+push sequence
        $pattern1 = { E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }  // call+test+je sequence
        $pattern2 = { FF 15 ?? ?? ?? ?? FF 15 2C A1 15 01 }  // CloseHandle+ExitProcess call

    condition:
        any of them
}