rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }  // test + je
        $pattern1 = { FF D7 8B CE E8 ?? ?? ?? ?? }  // call + mov + call (exit func)
        $pattern2 = { B8 ?? ?? ?? ?? C3 }  // mov eax,imm32 + ret

    condition:
        any of them
}