rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 48 83 F8 FF 74 4E }  // cmp rax, FFFF... + je
        $pattern1 = { FF 15 F1 0E 00 00 48 8B F8 }  // call + mov rdi, rax
        $pattern2 = { FF 15 B2 0E 00 00 }  // call to ExitProcess

    condition:
        any of them
}