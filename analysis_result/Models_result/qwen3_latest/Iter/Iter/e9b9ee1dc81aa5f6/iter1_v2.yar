rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 3D 20 00 00 00 0F 82 ?? ?? ?? ?? }  // cmp eax, 20h + jnle
        $pattern1 = { FF 15 34 73 45 00 }                  // ShellExecuteW call
        $pattern2 = { FF 15 7C 72 45 00 }                  // ExitProcess call

    condition:
        any of them
}