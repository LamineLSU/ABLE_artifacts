rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? } // test + je
        $pattern1 = { 8B FF 55 8B EC E8 F7 25 00 00 } // mov edi,edi + push ebp + mov ebp,esp + call
        $pattern2 = { FF 15 A0 F1 42 00 } // call [0042F1A0h]

    condition:
        any of them
}