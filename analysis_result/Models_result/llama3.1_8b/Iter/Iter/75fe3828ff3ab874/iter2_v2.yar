rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }  // test+je+mov (specific stack offset)
        $pattern1 = { B8 04 01 00 00 FF D0 }  // push imm32 + call (concrete bytes, specific exit API check)
        $pattern2 = { DC ?? ?? ?? ?? ?? }  // timing check for evasion

    condition:
        any of them
}