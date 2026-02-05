rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 20 75 45 00 8D 95 94 FE FF FF }  // lstrcat + lea edx
        $pattern1 = { FF 15 84 75 45 00 6A 3C 8D 85 94 FE FF FF }  // ShellExecuteEx + push 0x3C
        $pattern2 = { E8 B1 25 02 00 68 04 01 00 00 8D 8D EC FE FF FF }  // _memset + push 0x104

    condition:
        any of them
}