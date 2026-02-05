rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }  // test+je+mov (evasion check)
        $pattern1 = { 50 E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }  // push+call+test+je (complex check)
        $pattern2 = { E8 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }  // call+call (exit decision flow)

    condition:
        any of them
}