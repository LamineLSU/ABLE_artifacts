rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 84 C0 74 2A }  // test al/al + je
        $pattern1 = { FF 15 28 63 45 00 }  // call to ShellExecuteW
        $pattern2 = { 83 F8 20 7E 07 }  // cmp eax/20h + jle

    condition:
        any of them
}