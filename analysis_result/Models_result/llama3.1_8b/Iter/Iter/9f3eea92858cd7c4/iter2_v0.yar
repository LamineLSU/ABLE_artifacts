rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? } // test + je
        $pattern1 = { E8 E3 FA FF FF E9 B5 FC FF FF } // call to exit
        $pattern2 = { 33 DB BA 21 05 00 00 53 53 68 40 11 A5 00 } // xor ebx + push imm32

    condition:
        any of them
}